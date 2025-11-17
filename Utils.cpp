// Utils.cpp
// Always include winsock2.h before windows.h to avoid redefinition errors
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include "Utils.h"
#pragma comment(lib, "ws2_32.lib")

namespace Utils {
    std::string GuidToString(const GUID& guid) {
        char buf[64];
        snprintf(buf, sizeof(buf),
            "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return std::string(buf);
    }
    GUID GetSublayerGuid() {
        // Use a hardcoded GUID for the sublayer (replace with your own for production)
        static const GUID SUBLAYER_GUID = {0x12345678,0x1234,0x5678,{0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef}};
        return SUBLAYER_GUID;
    }
    std::string SockaddrToString(DWORD ip, DWORD port) {
        struct in_addr addr; addr.S_un.S_addr = ip;
        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
        std::ostringstream oss; oss << ipStr << ":" << ntohs((u_short)port);
        return oss.str();
    }
    std::string Sockaddr6ToString(const BYTE ip6[16], DWORD port) {
        char ipStr[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, ip6, ipStr, INET6_ADDRSTRLEN);
        std::ostringstream oss; oss << "[" << ipStr << "]:" << ntohs((u_short)port);
        return oss.str();
    }
    std::string GetLastErrorAsString() {
        DWORD errorMessageID = ::GetLastError();
        if(errorMessageID == 0) return std::string();
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                    NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        return message;
    }
    std::string WideToUtf8(const std::wstring& w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
        std::string s; s.resize(len ? len - 1 : 0);
        if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, NULL, NULL);
        return s;
    }

    bool TestIPConnectivity(const std::string& ipAddress, int timeoutMs) {
        // Try to create a TCP connection to test if IP is reachable
        // If blocked by firewall, connection should fail
        SOCKET sock = INVALID_SOCKET;
        struct addrinfo hints = {}, *result = nullptr;
        
        hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP
        hints.ai_protocol = IPPROTO_TCP;
        
        // Try to resolve the IP address
        int res = getaddrinfo(ipAddress.c_str(), "80", &hints, &result);
        if (res != 0) {
            // Try port 443 if 80 fails
            res = getaddrinfo(ipAddress.c_str(), "443", &hints, &result);
            if (res != 0) {
                return false; // Can't resolve - treat as blocked
            }
        }
        
        bool connected = false;
        for (auto ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock == INVALID_SOCKET) {
                continue;
            }
            
            // Set socket to non-blocking for timeout control
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            
            // Attempt to connect
            connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);
            
            // Wait for connection or timeout
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            
            struct timeval tv;
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;
            
            int selectRes = select(0, nullptr, &writefds, nullptr, &tv);
            if (selectRes > 0) {
                // Check if connection succeeded
                int error = 0;
                int errorLen = sizeof(error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &errorLen);
                if (error == 0) {
                    connected = true;
                    closesocket(sock);
                    break;
                }
            }
            
            closesocket(sock);
        }
        
        if (result) {
            freeaddrinfo(result);
        }
        
        return connected;
    }
}
