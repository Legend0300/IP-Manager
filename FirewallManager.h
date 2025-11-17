// FirewallManager.h
// Minimal IP-based firewall management using WFP
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "Models.h"

class FirewallManager {
public:
    FirewallManager();
    ~FirewallManager();

    bool Initialize();
    bool BlockIP(const std::string& ipAddress, std::optional<std::uint16_t> port = std::nullopt);
    bool RemovePortBlock(const std::string& ipAddress, std::uint16_t port);
    bool UnblockIP(const std::string& ipAddress);
    std::vector<RuleEntry> ListRules() const;
    void ClearRules();
    bool EnableWhitelistMode();
    bool DisableWhitelistMode();
    bool IsWhitelistMode() const { return whitelistMode; }
    bool WhitelistIP(const std::string& ipAddress,
                     std::optional<std::vector<std::uint16_t>> ports = std::nullopt);
    bool AllowPortsForIP(const std::string& ipAddress, const std::vector<std::uint16_t>& ports);
    bool RemoveWhitelistPort(const std::string& ipAddress, std::uint16_t port);
    bool RemoveWhitelistedIP(const std::string& ipAddress);

private:
    bool AddSublayer();
    bool AddFilterForIP(const std::string& ipAddress,
                        const GUID& layer,
                        UINT64& outFilterId);
    bool AddBlockFiltersForPort(const std::string& ipAddress,
                                std::uint16_t port,
                                std::vector<UINT64>& outFilterIds);
    bool AddDefaultBlockFilters();
    void RemoveDefaultBlockFilters();

    bool AddOutboundPermitFilters(const std::string& ipAddress,
                                  std::optional<std::uint16_t> port,
                                  std::vector<UINT64>& outFilterIds);
    bool AddInboundPermitFilters(const std::string& ipAddress,
                                 std::optional<std::uint16_t> port,
                                 std::vector<UINT64>& outFilterIds);

    HANDLE engineHandle; // FWPM_SESSION0*
    bool wsaInitialized;
    int nextSerial;
    std::vector<RuleEntry> rules;
    bool whitelistMode;
    std::vector<UINT64> defaultBlockFilterIds;
};
