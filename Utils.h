// Utils.h
// Helper functions for GUID, error handling, formatting
#pragma once
#include <string>
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Include winsock2 before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <guiddef.h>

namespace Utils {
    std::string GuidToString(const GUID& guid);
    GUID GetSublayerGuid();
    std::string SockaddrToString(DWORD ip, DWORD port);
    // Format IPv6 address (16-byte) and port
    std::string Sockaddr6ToString(const BYTE ip6[16], DWORD port);
    std::string GetLastErrorAsString();
    // UTF conversions
    std::string WideToUtf8(const std::wstring& w);
    // IP connectivity test
    bool TestIPConnectivity(const std::string& ipAddress, int timeoutMs = 2000);
}
