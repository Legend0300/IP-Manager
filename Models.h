// Models.h
// Data structures for IP firewall rules
#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct PortRule {
    std::uint16_t port = 0;
    std::vector<std::uint64_t> filterIds;
};

struct RuleEntry {
    int serial = 0;
    std::string ipAddress;
    std::vector<std::uint64_t> filterIds; // WFP filter IDs for this IP
    bool isWhitelist = false;             // true when entry represents a permit rule
    bool allPorts = false;                // true when rule covers all ports for this IP
    std::vector<PortRule> portRules;      // per-port filters when not covering all ports
};
