// FirewallManager.cpp
// Minimal IP-based firewall management using the Windows Filtering Platform

#include <winsock2.h>
#include <ws2tcpip.h>

#include "FirewallManager.h"
#include "Utils.h"

#include <fwpmu.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <optional>
#include <set>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

GUID GetAppGateSublayerGuid() {
    static const GUID guid = {0x7f8ea3c1, 0x59b4, 0x4a61, {0x98, 0x3b, 0x5e, 0xe5, 0x5d, 0xac, 0x58, 0x6d}};
    return guid;
}

std::wstring ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (length <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(length - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), length);
    return result;
}

bool ParseIPv4HostOrder(const std::string& ip, UINT32& outHostOrder) {
    IN_ADDR addr{};
    if (InetPtonA(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }
    outHostOrder = ntohl(addr.S_un.S_addr);
    return true;
}

bool ParseIPv6(const std::string& ip, UINT8 outBytes[16]) {
    IN6_ADDR addr{};
    if (InetPtonA(AF_INET6, ip.c_str(), &addr) != 1) {
        return false;
    }
    memcpy(outBytes, addr.s6_addr, 16);
    return true;
}

bool IsIPv6(const std::string& ip) {
    return ip.find(':') != std::string::npos;
}

std::string DescribeFwpmStatus(DWORD status) {
    wchar_t* buffer = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS;
    HMODULE module = GetModuleHandleW(L"fwpuclnt.dll");
    DWORD length = FormatMessageW(flags,
                                  module,
                                  status,
                                  0,
                                  reinterpret_cast<LPWSTR>(&buffer),
                                  0,
                                  nullptr);
    std::string message;
    if (length != 0 && buffer) {
        message = Utils::WideToUtf8(buffer);
        LocalFree(buffer);
    }
    return message;
}

struct LayerConfig {
    const GUID* layer;
    bool useRemotePort;
    const wchar_t* directionLabel;
};

const LayerConfig kOutboundPermitLayers[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, true, L"Connect"},
    {&FWPM_LAYER_OUTBOUND_TRANSPORT_V4, true, L"Outbound"},
};

const LayerConfig kInboundPermitLayers[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false, L"Accept"},
    {&FWPM_LAYER_INBOUND_TRANSPORT_V4, false, L"Inbound"},
};

const LayerConfig kOutboundPermitLayersV6[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, L"Connect6"},
    {&FWPM_LAYER_OUTBOUND_TRANSPORT_V6, true, L"Outbound6"},
};

const LayerConfig kInboundPermitLayersV6[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, false, L"Accept6"},
    {&FWPM_LAYER_INBOUND_TRANSPORT_V6, false, L"Inbound6"},
};

const LayerConfig kOutboundBlockLayers[] = {
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, true, L"Connect"},
    {&FWPM_LAYER_OUTBOUND_TRANSPORT_V4, true, L"Outbound"},
    {&FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, L"Connect6"},
    {&FWPM_LAYER_OUTBOUND_TRANSPORT_V6, true, L"Outbound6"},
};

const LayerConfig kInboundBlockLayers[] = {
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false, L"Accept"},
    {&FWPM_LAYER_INBOUND_TRANSPORT_V4, false, L"Inbound"},
    {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, false, L"Accept6"},
    {&FWPM_LAYER_INBOUND_TRANSPORT_V6, false, L"Inbound6"},
};

} // namespace

FirewallManager::FirewallManager()
    : engineHandle(nullptr), wsaInitialized(false), nextSerial(1), whitelistMode(false) {}

FirewallManager::~FirewallManager() {
    ClearRules();
    DisableWhitelistMode();

    if (engineHandle) {
        FwpmEngineClose0(engineHandle);
        engineHandle = nullptr;
    }

    if (wsaInitialized) {
        WSACleanup();
        wsaInitialized = false;
    }
}

bool FirewallManager::Initialize() {
    if (!wsaInitialized) {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            std::cerr << "[!] WSAStartup failed.\n";
            return false;
        }
        wsaInitialized = true;
    }

    if (engineHandle) {
        return true;
    }

    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"AppGate Session");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    HANDLE handle = nullptr;
    const DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &handle);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[!] FwpmEngineOpen0 failed (status=" << status << ").\n";
        return false;
    }

    engineHandle = handle;
    if (!AddSublayer()) {
        std::cerr << "[!] Failed to add WFP sublayer.\n";
        return false;
    }

    return true;
}

bool FirewallManager::AddSublayer() {
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = GetAppGateSublayerGuid();
    sublayer.displayData.name = const_cast<wchar_t*>(L"AppGateSublayer");
    sublayer.displayData.description = const_cast<wchar_t*>(L"Custom sublayer for AppGate");
    sublayer.flags = 0;
    sublayer.weight = 0x100;
    DWORD status = FwpmSubLayerAdd0((HANDLE)engineHandle, &sublayer, NULL);
    return status == ERROR_SUCCESS || status == FWP_E_ALREADY_EXISTS;
}

bool FirewallManager::AddFilterForIP(const std::string& ipAddress,
                                     const GUID& layer,
                                     UINT64& outFilterId) {
    bool isV6 = IsIPv6(ipAddress);
    UINT32 hostOrderIP = 0;
    UINT8 ipv6Bytes[16] = {};

    if (isV6) {
        if (!ParseIPv6(ipAddress, ipv6Bytes)) {
            std::cerr << "[!] Invalid IPv6 address: " << ipAddress << "\n";
            return false;
        }
    } else {
        if (!ParseIPv4HostOrder(ipAddress, hostOrderIP)) {
            std::cerr << "[!] Invalid IPv4 address: " << ipAddress << "\n";
            return false;
        }
    }

    FWP_BYTE_ARRAY16 addrV6 = {0};

    FWPM_FILTER_CONDITION0 condition = {0};
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    if (isV6) {
        memcpy(addrV6.byteArray16, ipv6Bytes, 16);
        condition.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        condition.conditionValue.byteArray16 = &addrV6;
    } else {
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = hostOrderIP;
    }

    std::wstring ruleName = ToWide(ipAddress) + L"-Block";

    FWPM_FILTER0 filter = {0};
    filter.filterKey = {0};
    filter.layerKey = layer;
    filter.displayData.name = const_cast<wchar_t*>(ruleName.c_str());
    filter.displayData.description = const_cast<wchar_t*>(L"Block IP address");
    filter.action.type = FWP_ACTION_BLOCK;
    filter.subLayerKey = GetAppGateSublayerGuid();
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;

    DWORD status = FwpmFilterAdd0(engineHandle, &filter, nullptr, &outFilterId);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[!] FwpmFilterAdd0 failed (status=" << status << ") for IP: " << ipAddress
                  << " :: " << DescribeFwpmStatus(status) << "\n";
        return false;
    }

    return true;
}

bool FirewallManager::AddBlockFiltersForPort(const std::string& ipAddress,
                                             std::uint16_t port,
                                             std::vector<UINT64>& outFilterIds) {
    if (port == 0) {
        std::cerr << "[!] Port 0 is not valid for blocking.\n";
        return false;
    }

    bool isV6 = IsIPv6(ipAddress);
    UINT32 hostOrderIP = 0;
    UINT8 ipv6Bytes[16] = {};

    if (isV6) {
        if (!ParseIPv6(ipAddress, ipv6Bytes)) {
            std::cerr << "[!] Invalid IPv6 address: " << ipAddress << "\n";
            return false;
        }
    } else {
        if (!ParseIPv4HostOrder(ipAddress, hostOrderIP)) {
            std::cerr << "[!] Invalid IPv4 address: " << ipAddress << "\n";
            return false;
        }
    }

    static const UINT8 kProtocols[] = {IPPROTO_TCP, IPPROTO_UDP};
    std::vector<UINT64> created;

    auto addFiltersForLayers = [&](const LayerConfig* layers, std::size_t startIndex, bool outbound) -> bool {
        for (std::size_t layerIndex = startIndex; layerIndex < startIndex + 2; ++layerIndex) {
            const auto& layerCfg = layers[layerIndex];
            for (UINT8 protocol : kProtocols) {
                FWP_BYTE_ARRAY16 addrV6 = {0};
                FWPM_FILTER_CONDITION0 conditions[3] = {};

                conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conditions[0].matchType = FWP_MATCH_EQUAL;
                if (isV6) {
                    memcpy(addrV6.byteArray16, ipv6Bytes, 16);
                    conditions[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
                    conditions[0].conditionValue.byteArray16 = &addrV6;
                } else {
                    conditions[0].conditionValue.type = FWP_UINT32;
                    conditions[0].conditionValue.uint32 = hostOrderIP;
                }

                conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                conditions[1].matchType = FWP_MATCH_EQUAL;
                conditions[1].conditionValue.type = FWP_UINT8;
                conditions[1].conditionValue.uint8 = protocol;

                conditions[2].fieldKey = layerCfg.useRemotePort ? FWPM_CONDITION_IP_REMOTE_PORT
                                                                : FWPM_CONDITION_IP_LOCAL_PORT;
                conditions[2].matchType = FWP_MATCH_EQUAL;
                conditions[2].conditionValue.type = FWP_UINT16;
                conditions[2].conditionValue.uint16 = port;

                std::wstring ruleName = ToWide(ipAddress);
                ruleName += outbound ? L" Block Out " : L" Block In ";
                ruleName += layerCfg.directionLabel;
                ruleName += L" ";
                ruleName += (protocol == IPPROTO_TCP) ? L"TCP" : L"UDP";
                ruleName += L"/";
                ruleName += std::to_wstring(port);

                FWPM_FILTER0 filter = {0};
                filter.layerKey = *layerCfg.layer;
                filter.displayData.name = const_cast<wchar_t*>(ruleName.c_str());
                filter.displayData.description = const_cast<wchar_t*>(L"Specific port block");
                filter.action.type = FWP_ACTION_BLOCK;
                filter.subLayerKey = GetAppGateSublayerGuid();
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 15;
                filter.numFilterConditions = 3;
                filter.filterCondition = conditions;

                UINT64 filterId = 0;
                DWORD status = FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
                if (status != ERROR_SUCCESS) {
                    std::cerr << "[!] FwpmFilterAdd0 (port block) failed (status=" << status << ") for IP: "
                              << ipAddress << " port: " << port << " proto: "
                              << static_cast<int>(protocol) << " layer=" << layerCfg.directionLabel
                              << " :: " << DescribeFwpmStatus(status) << "\n";
                    for (UINT64 id : created) {
                        FwpmFilterDeleteById0(engineHandle, id);
                    }
                    return false;
                }

                created.push_back(filterId);
            }
        }
        return true;
    };

    std::size_t outboundOffset = isV6 ? 2 : 0;
    if (!addFiltersForLayers(kOutboundBlockLayers, outboundOffset, /*outbound=*/true)) {
        return false;
    }

    std::size_t inboundOffset = isV6 ? 2 : 0;
    if (!addFiltersForLayers(kInboundBlockLayers, inboundOffset, /*outbound=*/false)) {
        return false;
    }

    outFilterIds.insert(outFilterIds.end(), created.begin(), created.end());
    return true;
}

bool FirewallManager::AddOutboundPermitFilters(const std::string& ipAddress,
                                               std::optional<std::uint16_t> port,
                                               std::vector<UINT64>& outFilterIds) {
    bool isV6 = IsIPv6(ipAddress);
    UINT32 hostOrderIP = 0;
    UINT8 ipv6Bytes[16] = {};

    if (isV6) {
        if (!ParseIPv6(ipAddress, ipv6Bytes)) {
            std::cerr << "[!] Invalid IPv6 address: " << ipAddress << "\n";
            return false;
        }
    } else {
        if (!ParseIPv4HostOrder(ipAddress, hostOrderIP)) {
            std::cerr << "[!] Invalid IPv4 address: " << ipAddress << "\n";
            return false;
        }
    }

    std::vector<UINT64> created;
    static UINT64 permitWeight = 0xFFFFFFFFFFFFFFF0ULL;

    const LayerConfig* layers = isV6 ? kOutboundPermitLayersV6 : kOutboundPermitLayers;
    size_t layerCount = 2;

    auto addFilterForLayer = [&](const LayerConfig& layerCfg,
                                 std::optional<std::uint16_t> portValue,
                                 UINT8 protocol) -> bool {
        FWP_BYTE_ARRAY16 addrV6 = {0};
        FWPM_FILTER_CONDITION0 conditions[3] = {};
        UINT32 conditionCount = 1;

        conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        if (isV6) {
            memcpy(addrV6.byteArray16, ipv6Bytes, 16);
            conditions[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            conditions[0].conditionValue.byteArray16 = &addrV6;
        } else {
            conditions[0].conditionValue.type = FWP_UINT32;
            conditions[0].conditionValue.uint32 = hostOrderIP;
        }

        if (portValue.has_value()) {
            conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            conditions[1].matchType = FWP_MATCH_EQUAL;
            conditions[1].conditionValue.type = FWP_UINT8;
            conditions[1].conditionValue.uint8 = protocol;

            conditions[2].fieldKey = layerCfg.useRemotePort ? FWPM_CONDITION_IP_REMOTE_PORT
                                                            : FWPM_CONDITION_IP_LOCAL_PORT;
            conditions[2].matchType = FWP_MATCH_EQUAL;
            conditions[2].conditionValue.type = FWP_UINT16;
            conditions[2].conditionValue.uint16 = portValue.value();

            conditionCount = 3;
        }

        std::wstring ruleName = ToWide(ipAddress);
        ruleName += L" Allow ";
        ruleName += layerCfg.directionLabel;
        if (portValue.has_value()) {
            ruleName += L" ";
            ruleName += (protocol == IPPROTO_TCP) ? L"TCP" : L"UDP";
            ruleName += L"/";
            ruleName += std::to_wstring(portValue.value());
        }

        FWPM_FILTER0 filter = {0};
        filter.layerKey = *layerCfg.layer;
        filter.displayData.name = const_cast<wchar_t*>(ruleName.c_str());
        filter.displayData.description = const_cast<wchar_t*>(L"Whitelist permit outbound");
        filter.action.type = FWP_ACTION_PERMIT;
        filter.subLayerKey = GetAppGateSublayerGuid();
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.weight.type = FWP_UINT64;
        filter.weight.uint64 = &permitWeight;
        filter.numFilterConditions = conditionCount;
        filter.filterCondition = conditions;

        UINT64 filterId = 0;
        DWORD status = FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] FwpmFilterAdd0 (outbound permit) failed (status=" << status << ") for IP: "
                      << ipAddress << " layer=" << layerCfg.directionLabel << " :: " << DescribeFwpmStatus(status) << "\n";
            for (UINT64 id : created) {
                FwpmFilterDeleteById0(engineHandle, id);
            }
            return false;
        }

        created.push_back(filterId);
        return true;
    };

    if (port.has_value()) {
        static const UINT8 kProtocols[] = {IPPROTO_TCP, IPPROTO_UDP};
        for (size_t i = 0; i < layerCount; ++i) {
            const auto& layerCfg = layers[i];
            for (UINT8 protocol : kProtocols) {
                if (!addFilterForLayer(layerCfg, port, protocol)) {
                    return false;
                }
            }
        }
    } else {
        for (size_t i = 0; i < layerCount; ++i) {
            if (!addFilterForLayer(layers[i], std::nullopt, 0)) {
                return false;
            }
        }
    }

    outFilterIds.insert(outFilterIds.end(), created.begin(), created.end());
    return true;
}

bool FirewallManager::AddInboundPermitFilters(const std::string& ipAddress,
                                              std::optional<std::uint16_t> port,
                                              std::vector<UINT64>& outFilterIds) {
    bool isV6 = IsIPv6(ipAddress);
    UINT32 hostOrderIP = 0;
    UINT8 ipv6Bytes[16] = {};

    if (isV6) {
        if (!ParseIPv6(ipAddress, ipv6Bytes)) {
            std::cerr << "[!] Invalid IPv6 address: " << ipAddress << "\n";
            return false;
        }
    } else {
        if (!ParseIPv4HostOrder(ipAddress, hostOrderIP)) {
            std::cerr << "[!] Invalid IPv4 address: " << ipAddress << "\n";
            return false;
        }
    }

    std::vector<UINT64> created;
    static UINT64 permitWeight = 0xFFFFFFFFFFFFFFF0ULL;

    const LayerConfig* layers = isV6 ? kInboundPermitLayersV6 : kInboundPermitLayers;
    size_t layerCount = 2;

    auto addFilterForLayer = [&](const LayerConfig& layerCfg,
                                 std::optional<std::uint16_t> portValue,
                                 UINT8 protocol) -> bool {
        FWP_BYTE_ARRAY16 addrV6 = {0};
        FWPM_FILTER_CONDITION0 conditions[3] = {};
        UINT32 conditionCount = 1;

        conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        if (isV6) {
            memcpy(addrV6.byteArray16, ipv6Bytes, 16);
            conditions[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            conditions[0].conditionValue.byteArray16 = &addrV6;
        } else {
            conditions[0].conditionValue.type = FWP_UINT32;
            conditions[0].conditionValue.uint32 = hostOrderIP;
        }

        if (portValue.has_value()) {
            conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            conditions[1].matchType = FWP_MATCH_EQUAL;
            conditions[1].conditionValue.type = FWP_UINT8;
            conditions[1].conditionValue.uint8 = protocol;

            conditions[2].fieldKey = layerCfg.useRemotePort ? FWPM_CONDITION_IP_REMOTE_PORT
                                                            : FWPM_CONDITION_IP_LOCAL_PORT;
            conditions[2].matchType = FWP_MATCH_EQUAL;
            conditions[2].conditionValue.type = FWP_UINT16;
            conditions[2].conditionValue.uint16 = portValue.value();

            conditionCount = 3;
        }

        std::wstring ruleName = ToWide(ipAddress);
        ruleName += L" Allow ";
        ruleName += layerCfg.directionLabel;
        if (portValue.has_value()) {
            ruleName += L" ";
            ruleName += (protocol == IPPROTO_TCP) ? L"TCP" : L"UDP";
            ruleName += L"/";
            ruleName += std::to_wstring(portValue.value());
        }

        FWPM_FILTER0 filter = {0};
        filter.layerKey = *layerCfg.layer;
        filter.displayData.name = const_cast<wchar_t*>(ruleName.c_str());
        filter.displayData.description = const_cast<wchar_t*>(L"Whitelist permit inbound");
        filter.action.type = FWP_ACTION_PERMIT;
        filter.subLayerKey = GetAppGateSublayerGuid();
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.weight.type = FWP_UINT64;
        filter.weight.uint64 = &permitWeight;
        filter.numFilterConditions = conditionCount;
        filter.filterCondition = conditions;

        UINT64 filterId = 0;
        DWORD status = FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] FwpmFilterAdd0 (inbound permit) failed (status=" << status << ") for IP: "
                      << ipAddress << " layer=" << layerCfg.directionLabel << " :: " << DescribeFwpmStatus(status) << "\n";
            for (UINT64 id : created) {
                FwpmFilterDeleteById0(engineHandle, id);
            }
            return false;
        }

        created.push_back(filterId);
        return true;
    };

    if (port.has_value()) {
        static const UINT8 kProtocols[] = {IPPROTO_TCP, IPPROTO_UDP};
        for (size_t i = 0; i < layerCount; ++i) {
            const auto& layerCfg = layers[i];
            for (UINT8 protocol : kProtocols) {
                if (!addFilterForLayer(layerCfg, port, protocol)) {
                    return false;
                }
            }
        }
    } else {
        for (size_t i = 0; i < layerCount; ++i) {
            if (!addFilterForLayer(layers[i], std::nullopt, 0)) {
                return false;
            }
        }
    }

    outFilterIds.insert(outFilterIds.end(), created.begin(), created.end());
    return true;
}

bool FirewallManager::AddDefaultBlockFilters() {
    std::vector<UINT64> added;
    static UINT64 blockWeight = 0x100ULL;

    auto addFilter = [&](const LayerConfig& layerCfg,
                         bool outbound) -> bool {
        std::wstring ruleName = outbound ? L"Block Out " : L"Block In ";
        ruleName += layerCfg.directionLabel;

        FWPM_FILTER0 filter = {0};
        filter.layerKey = *layerCfg.layer;
        filter.displayData.name = const_cast<wchar_t*>(ruleName.c_str());
        filter.displayData.description = const_cast<wchar_t*>(L"Whitelist default deny");
        filter.action.type = FWP_ACTION_BLOCK;
        filter.subLayerKey = GetAppGateSublayerGuid();
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.weight.type = FWP_UINT64;
        filter.weight.uint64 = &blockWeight;
        filter.numFilterConditions = 0;
        filter.filterCondition = nullptr;

        UINT64 filterId = 0;
        DWORD status = FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] Failed to add default block filter (status=" << status << ") :: "
                      << DescribeFwpmStatus(status) << "\n";
            return false;
        }

        added.push_back(filterId);
        return true;
    };

    for (const auto& layerCfg : kOutboundBlockLayers) {
        if (!addFilter(layerCfg, /*outbound=*/true)) {
            for (UINT64 id : added) {
                FwpmFilterDeleteById0(engineHandle, id);
            }
            return false;
        }
    }

    for (const auto& layerCfg : kInboundBlockLayers) {
        if (!addFilter(layerCfg, /*outbound=*/false)) {
            for (UINT64 id : added) {
                FwpmFilterDeleteById0(engineHandle, id);
            }
            return false;
        }
    }

    defaultBlockFilterIds.insert(defaultBlockFilterIds.end(), added.begin(), added.end());
    return true;
}

void FirewallManager::RemoveDefaultBlockFilters() {
    for (UINT64 id : defaultBlockFilterIds) {
        DWORD status = FwpmFilterDeleteById0(engineHandle, id);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] Failed to remove default block filter id " << id << " (status=" << status
                      << ") :: " << DescribeFwpmStatus(status) << "\n";
        }
    }
    defaultBlockFilterIds.clear();
}

bool FirewallManager::EnableWhitelistMode() {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }
    if (whitelistMode) {
        return true;
    }

    RemoveDefaultBlockFilters();
    if (!AddDefaultBlockFilters()) {
        return false;
    }

    whitelistMode = true;
    std::cout << "[+] Whitelist mode enabled. All traffic is blocked by default.\n";
    return true;
}

bool FirewallManager::DisableWhitelistMode() {
    if (!engineHandle) {
        whitelistMode = false;
        defaultBlockFilterIds.clear();
        return true;
    }

    if (!whitelistMode && defaultBlockFilterIds.empty()) {
        return true;
    }

    RemoveDefaultBlockFilters();
    whitelistMode = false;
    std::cout << "[+] Whitelist mode disabled.\n";
    return true;
}

bool FirewallManager::WhitelistIP(const std::string& ipAddress,
                                  std::optional<std::vector<std::uint16_t>> ports) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }
    if (!whitelistMode) {
        std::cerr << "[!] Whitelist mode is not enabled.\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return rule.ipAddress == ipAddress; });
    if (it != rules.end() && !it->isWhitelist) {
        std::cerr << "[!] IP " << ipAddress << " is currently blocked. Remove the block first.\n";
        return false;
    }

    if (!ports.has_value()) {
        std::vector<UINT64> added;

        if (it == rules.end()) {
            if (!AddOutboundPermitFilters(ipAddress, std::nullopt, added)) {
                return false;
            }
            if (!AddInboundPermitFilters(ipAddress, std::nullopt, added)) {
                for (UINT64 id : added) {
                    FwpmFilterDeleteById0(engineHandle, id);
                }
                return false;
            }

            RuleEntry newRule;
            newRule.serial = nextSerial++;
            newRule.ipAddress = ipAddress;
            newRule.isWhitelist = true;
            newRule.allPorts = true;
            newRule.filterIds = added;
            rules.push_back(std::move(newRule));
            std::cout << "[+] Whitelisted IP: " << ipAddress << " (serial: " << rules.back().serial
                      << ") with all ports allowed\n";
            return true;
        }

        RuleEntry& entry = *it;
        if (entry.allPorts) {
            std::cout << "[+] IP " << ipAddress << " already allows all ports.\n";
            return true;
        }

        // Remove existing port-specific permits
        for (const auto& portRule : entry.portRules) {
            for (UINT64 filterId : portRule.filterIds) {
                DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
                if (status != ERROR_SUCCESS) {
                    std::cerr << "[!] Failed to remove permit filter ID " << filterId << " (status=" << status
                              << ") :: " << DescribeFwpmStatus(status) << "\n";
                }
            }
        }
        entry.portRules.clear();
        entry.filterIds.clear();

        if (!AddOutboundPermitFilters(ipAddress, std::nullopt, added)) {
            return false;
        }
        if (!AddInboundPermitFilters(ipAddress, std::nullopt, added)) {
            for (UINT64 id : added) {
                FwpmFilterDeleteById0(engineHandle, id);
            }
            return false;
        }

        entry.filterIds = added;
        entry.allPorts = true;
        std::cout << "[+] Updated IP " << ipAddress << " to allow all ports.\n";
        return true;
    }

    std::set<std::uint16_t> normalized;
    for (std::uint16_t portValue : *ports) {
        if (portValue == 0 || portValue > 65535) {
            std::cerr << "[!] Invalid port number: " << portValue << "\n";
            return false;
        }
        normalized.insert(portValue);
    }

    if (normalized.empty()) {
        std::cerr << "[!] No valid ports provided for whitelisting.\n";
        return false;
    }

    std::vector<std::uint16_t> dedupPorts(normalized.begin(), normalized.end());
    return AllowPortsForIP(ipAddress, dedupPorts);
}

bool FirewallManager::AllowPortsForIP(const std::string& ipAddress,
                                      const std::vector<std::uint16_t>& ports) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }
    if (!whitelistMode) {
        std::cerr << "[!] Whitelist mode is not enabled.\n";
        return false;
    }
    if (ports.empty()) {
        std::cerr << "[!] No ports supplied.\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return rule.ipAddress == ipAddress; });
    if (it != rules.end() && !it->isWhitelist) {
        std::cerr << "[!] IP " << ipAddress << " is currently blocked. Remove the block first.\n";
        return false;
    }

    RuleEntry* entry = nullptr;
    bool createdRule = false;
    if (it == rules.end()) {
        RuleEntry newRule;
        newRule.serial = nextSerial++;
        newRule.ipAddress = ipAddress;
        newRule.isWhitelist = true;
        newRule.allPorts = false;
        rules.push_back(std::move(newRule));
        entry = &rules.back();
        createdRule = true;
    } else {
        entry = &(*it);
        if (entry->allPorts) {
            for (UINT64 filterId : entry->filterIds) {
                DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
                if (status != ERROR_SUCCESS) {
                    std::cerr << "[!] Failed to remove whitelist filter ID " << filterId << " (status=" << status
                              << ") :: " << DescribeFwpmStatus(status) << "\n";
                }
            }
            entry->filterIds.clear();
            entry->portRules.clear();
            entry->allPorts = false;
        }
    }

    auto removeFilters = [&](const std::vector<UINT64>& ids) {
        for (UINT64 id : ids) {
            DWORD status = FwpmFilterDeleteById0(engineHandle, id);
            if (status != ERROR_SUCCESS && status != FWP_E_FILTER_NOT_FOUND) {
                std::cerr << "[!] Failed to remove permit filter ID " << id << " (status=" << status
                          << ") :: " << DescribeFwpmStatus(status) << "\n";
            }
        }
    };

    std::vector<PortRule> pendingRules;
    std::vector<UINT64> pendingIds;

    for (std::uint16_t portValue : ports) {
        auto alreadyAllowed = std::find_if(entry->portRules.begin(), entry->portRules.end(),
                                           [&](const PortRule& pr) { return pr.port == portValue; });
        if (alreadyAllowed != entry->portRules.end()) {
            std::cout << "[i] Port " << portValue << " is already allowed for IP " << ipAddress << ".\n";
            continue;
        }

        PortRule portRule;
        portRule.port = portValue;
        std::vector<UINT64> portFilterIds;

        if (!AddOutboundPermitFilters(ipAddress, portValue, portFilterIds)) {
            removeFilters(portFilterIds);
            removeFilters(pendingIds);
            if (createdRule && entry == &rules.back()) {
                rules.pop_back();
                --nextSerial;
            }
            return false;
        }

        if (!AddInboundPermitFilters(ipAddress, portValue, portFilterIds)) {
            removeFilters(portFilterIds);
            removeFilters(pendingIds);
            if (createdRule && entry == &rules.back()) {
                rules.pop_back();
                --nextSerial;
            }
            return false;
        }

        portRule.filterIds = portFilterIds;
        pendingIds.insert(pendingIds.end(), portFilterIds.begin(), portFilterIds.end());
        pendingRules.push_back(std::move(portRule));
    }

    if (pendingRules.empty()) {
        if (createdRule && entry == &rules.back() && entry->portRules.empty()) {
            rules.pop_back();
            --nextSerial;
        }
        std::cout << "[i] No new ports were added for IP " << ipAddress << ".\n";
        return true;
    }

    entry->filterIds.insert(entry->filterIds.end(), pendingIds.begin(), pendingIds.end());
    entry->portRules.insert(entry->portRules.end(), pendingRules.begin(), pendingRules.end());
    entry->allPorts = false;

    std::cout << "[+] Allowed ports for IP " << ipAddress << ":";
    for (const auto& pr : pendingRules) {
        std::cout << ' ' << pr.port;
    }
    std::cout << "\n";
    return true;
}

bool FirewallManager::RemoveWhitelistPort(const std::string& ipAddress, std::uint16_t port) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }
    if (!whitelistMode) {
        std::cerr << "[!] Whitelist mode is not enabled.\n";
        return false;
    }
    if (port == 0 || port > 65535) {
        std::cerr << "[!] Invalid port number: " << port << "\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return rule.isWhitelist && rule.ipAddress == ipAddress; });
    if (it == rules.end()) {
        std::cerr << "[!] IP " << ipAddress << " is not whitelisted.\n";
        return false;
    }

    RuleEntry& entry = *it;
    if (entry.allPorts) {
        std::cerr << "[!] IP " << ipAddress << " currently allows all ports. Switch to specific ports first.\n";
        return false;
    }

    auto portIt = std::find_if(entry.portRules.begin(), entry.portRules.end(),
                               [&](const PortRule& pr) { return pr.port == port; });
    if (portIt == entry.portRules.end()) {
        std::cerr << "[!] Port " << port << " is not allowed for IP " << ipAddress << ".\n";
        return false;
    }

    auto removeFilters = [&](const std::vector<UINT64>& ids) {
        for (UINT64 id : ids) {
            DWORD status = FwpmFilterDeleteById0(engineHandle, id);
            if (status != ERROR_SUCCESS && status != FWP_E_FILTER_NOT_FOUND) {
                std::cerr << "[!] Failed to remove whitelist filter ID " << id << " (status=" << status
                          << ") :: " << DescribeFwpmStatus(status) << "\n";
            }
        }
    };

    removeFilters(portIt->filterIds);

    for (UINT64 id : portIt->filterIds) {
        auto idIt = std::find(entry.filterIds.begin(), entry.filterIds.end(), id);
        if (idIt != entry.filterIds.end()) {
            entry.filterIds.erase(idIt);
        }
    }

    entry.portRules.erase(portIt);

    if (entry.portRules.empty()) {
        rules.erase(it);
        std::cout << "[+] Removed port " << port << " and removed IP " << ipAddress
                  << " from the whitelist (no ports allowed).\n";
    } else {
        std::cout << "[+] Removed allowed port " << port << " for IP " << ipAddress << ".\n";
    }

    return true;
}

bool FirewallManager::RemoveWhitelistedIP(const std::string& ipAddress) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return rule.isWhitelist && rule.ipAddress == ipAddress; });
    if (it == rules.end()) {
        std::cerr << "[!] IP " << ipAddress << " is not whitelisted.\n";
        return false;
    }

    for (UINT64 filterId : it->filterIds) {
        DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] Failed to remove whitelist filter ID " << filterId << " (status=" << status
                      << ") :: " << DescribeFwpmStatus(status) << "\n";
        }
    }

    rules.erase(it);
    std::cout << "[+] Removed whitelisted IP: " << ipAddress << "\n";
    return true;
}

bool FirewallManager::BlockIP(const std::string& ipAddress, std::optional<std::uint16_t> port) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return rule.ipAddress == ipAddress; });
    if (it != rules.end() && it->isWhitelist) {
        std::cerr << "[!] IP " << ipAddress << " is currently whitelisted. Remove it from the whitelist first.\n";
        return false;
    }

    if (!port.has_value()) {
        if (it != rules.end() && !it->isWhitelist && it->allPorts) {
            std::cout << "[+] IP " << ipAddress << " is already blocked on all ports.\n";
            return true;
        }

        bool isV6 = IsIPv6(ipAddress);
        UINT64 outboundFilterId = 0;
        const GUID& outboundLayer = isV6 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        if (!AddFilterForIP(ipAddress, outboundLayer, outboundFilterId)) {
            return false;
        }

        UINT64 inboundFilterId = 0;
        const GUID& inboundLayer = isV6 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
        if (!AddFilterForIP(ipAddress, inboundLayer, inboundFilterId)) {
            FwpmFilterDeleteById0(engineHandle, outboundFilterId);
            return false;
        }

        if (it == rules.end()) {
            RuleEntry newRule;
            newRule.serial = nextSerial++;
            newRule.ipAddress = ipAddress;
            newRule.isWhitelist = false;
            newRule.allPorts = true;
            newRule.filterIds = {outboundFilterId, inboundFilterId};
            rules.push_back(std::move(newRule));
            std::cout << "[+] Blocked IP: " << ipAddress << " on all ports (serial: " << rules.back().serial << ")\n";
        } else {
            RuleEntry& existing = *it;
            if (!existing.isWhitelist) {
                std::vector<UINT64> oldFilters = existing.filterIds;
                for (UINT64 filterId : oldFilters) {
                    DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
                    if (status != ERROR_SUCCESS) {
                        std::cerr << "[!] Failed to remove filter ID " << filterId << " (status=" << status
                                  << ") :: " << DescribeFwpmStatus(status) << "\n";
                    }
                }

                existing.portRules.clear();
                existing.filterIds = {outboundFilterId, inboundFilterId};
                existing.allPorts = true;
                std::cout << "[+] Updated IP " << ipAddress << " to block all ports.\n";
            }
        }

        return true;
    }

    std::uint16_t portValue = port.value();
    if (portValue == 0 || portValue > 65535) {
        std::cerr << "[!] Invalid port number: " << portValue << "\n";
        return false;
    }

    RuleEntry* targetRule = nullptr;
    bool createdRule = false;
    if (it == rules.end()) {
        RuleEntry newRule;
        newRule.serial = nextSerial++;
        newRule.ipAddress = ipAddress;
        newRule.isWhitelist = false;
        newRule.allPorts = false;
        rules.push_back(std::move(newRule));
        targetRule = &rules.back();
        createdRule = true;
    } else {
        targetRule = &(*it);
        if (!targetRule->allPorts) {
            auto existingPort = std::find_if(targetRule->portRules.begin(), targetRule->portRules.end(),
                                             [&](const PortRule& pr) { return pr.port == portValue; });
            if (existingPort != targetRule->portRules.end()) {
                std::cout << "[+] IP " << ipAddress << " already blocks port " << portValue << ".\n";
                return true;
            }
        }
    }

    std::vector<UINT64> created;
    if (!AddBlockFiltersForPort(ipAddress, portValue, created)) {
        if (createdRule && targetRule == &rules.back()) {
            rules.pop_back();
            --nextSerial;
        }
        return false;
    }

    if (targetRule->allPorts) {
        for (UINT64 filterId : targetRule->filterIds) {
            DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
            if (status != ERROR_SUCCESS) {
                std::cerr << "[!] Failed to remove block-all filter ID " << filterId << " (status=" << status
                          << ") :: " << DescribeFwpmStatus(status) << "\n";
            }
        }
        targetRule->filterIds.clear();
        targetRule->portRules.clear();
        targetRule->allPorts = false;
    }

    targetRule->filterIds.insert(targetRule->filterIds.end(), created.begin(), created.end());
    PortRule portRule;
    portRule.port = portValue;
    portRule.filterIds = created;
    targetRule->portRules.push_back(std::move(portRule));

    std::cout << "[+] Blocked IP: " << ipAddress << " port " << portValue;
    if (createdRule) {
        std::cout << " (serial: " << targetRule->serial << ")";
    }
    std::cout << "\n";
    return true;
}

bool FirewallManager::RemovePortBlock(const std::string& ipAddress, std::uint16_t port) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return !rule.isWhitelist && rule.ipAddress == ipAddress; });
    if (it == rules.end()) {
        std::cerr << "[!] IP " << ipAddress << " is not blocked.\n";
        return false;
    }

    RuleEntry& entry = *it;
    if (entry.allPorts) {
        std::cerr << "[!] IP " << ipAddress << " blocks all ports. Remove the block or switch to specific ports first.\n";
        return false;
    }

    auto portIt = std::find_if(entry.portRules.begin(), entry.portRules.end(),
                               [&](const PortRule& pr) { return pr.port == port; });
    if (portIt == entry.portRules.end()) {
        std::cerr << "[!] Port " << port << " is not blocked for IP " << ipAddress << ".\n";
        return false;
    }

    for (UINT64 filterId : portIt->filterIds) {
        DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] Failed to remove filter ID " << filterId << " (status=" << status
                      << ") :: " << DescribeFwpmStatus(status) << "\n";
        }
        auto idIt = std::find(entry.filterIds.begin(), entry.filterIds.end(), filterId);
        if (idIt != entry.filterIds.end()) {
            entry.filterIds.erase(idIt);
        }
    }

    entry.portRules.erase(portIt);

    if (entry.portRules.empty()) {
        rules.erase(it);
        std::cout << "[+] Removed blocked port " << port << " and unblocked IP: " << ipAddress << "\n";
    } else {
        std::cout << "[+] Removed blocked port " << port << " for IP " << ipAddress << "\n";
    }

    return true;
}

bool FirewallManager::UnblockIP(const std::string& ipAddress) {
    if (!engineHandle) {
        std::cerr << "[!] Firewall engine not initialized.\n";
        return false;
    }

    auto it = std::find_if(rules.begin(), rules.end(),
                           [&](const RuleEntry& rule) { return !rule.isWhitelist && rule.ipAddress == ipAddress; });
    if (it == rules.end()) {
        std::cerr << "[!] IP " << ipAddress << " is not blocked.\n";
        return false;
    }

    for (UINT64 filterId : it->filterIds) {
        DWORD status = FwpmFilterDeleteById0(engineHandle, filterId);
        if (status != ERROR_SUCCESS) {
            std::cerr << "[!] Failed to remove filter ID " << filterId << " (status=" << status << ")\n";
        }
    }

    rules.erase(it);
    std::cout << "[+] Unblocked IP: " << ipAddress << "\n";
    return true;
}

std::vector<RuleEntry> FirewallManager::ListRules() const {
    return rules;
}

void FirewallManager::ClearRules() {
    if (!engineHandle) {
        return;
    }

    for (const auto& rule : rules) {
        for (UINT64 filterId : rule.filterIds) {
            FwpmFilterDeleteById0(engineHandle, filterId);
        }
    }
    rules.clear();
    nextSerial = 1;
}