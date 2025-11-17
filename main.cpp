// main.cpp
// CLI supporting blacklist and whitelist workflows for IP control
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "FirewallManager.h"
#include "Models.h"

enum class FirewallMode { Blacklist, Whitelist };

void PrintBanner();
FirewallMode PromptMode(FirewallManager& fm);
void PrintMenu(FirewallMode mode);
void HandleAddIP(FirewallManager& fm, FirewallMode mode);
void HandleRemoveIP(FirewallManager& fm, FirewallMode mode);
void HandleIPsFromFile(FirewallManager& fm, FirewallMode mode);
void ShowRules(FirewallManager& fm);
void ClearAllRules(FirewallManager& fm, FirewallMode mode);
void ManageBlockedIPs(FirewallManager& fm);
void EditBlockedIP(FirewallManager& fm, const std::string& ipAddress);
std::string DescribeBlockedPorts(const RuleEntry& rule);
void ManageWhitelistedIPs(FirewallManager& fm);
void EditWhitelistedIP(FirewallManager& fm, const std::string& ipAddress);
std::string DescribeAllowedPorts(const RuleEntry& rule);

struct WhitelistPortsRequest {
	bool allowAll = false;
	std::vector<std::uint16_t> ports;
};

enum class PortPromptResult { Success, Cancel };

static std::string ToLowerCopy(std::string value) {
	std::transform(value.begin(), value.end(), value.begin(),
		[](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
	return value;
}

static std::vector<std::string> Tokenize(const std::string& input) {
	std::istringstream iss(input);
	std::vector<std::string> tokens;
	std::string token;
	while (iss >> token) {
		tokens.push_back(token);
	}
	return tokens;
}

static bool ParseWhitelistPortTokens(const std::vector<std::string>& tokens,
	WhitelistPortsRequest& request,
	std::string& error) {
	if (tokens.empty()) {
		error = "Provide 'all' or at least one port number.";
		return false;
	}

	bool allowAll = false;
	std::set<std::uint16_t> dedup;

	for (const auto& token : tokens) {
		std::string lower = ToLowerCopy(token);
		if (lower == "all" || lower == "any" || lower == "*") {
			allowAll = true;
			break;
		}

		int value = 0;
		try {
			value = std::stoi(token);
		} catch (...) {
			error = "Invalid port '" + token + "'.";
			return false;
		}

		if (value <= 0 || value > 65535) {
			error = "Port out of range ('" + token + "').";
			return false;
		}

		dedup.insert(static_cast<std::uint16_t>(value));
	}

	if (allowAll) {
		request.allowAll = true;
		request.ports.clear();
		return true;
	}

	if (dedup.empty()) {
		error = "No valid ports provided.";
		return false;
	}

	request.allowAll = false;
	request.ports.assign(dedup.begin(), dedup.end());
	return true;
}

static PortPromptResult PromptWhitelistPorts(const std::string& prompt,
	WhitelistPortsRequest& request) {
	while (true) {
		std::cout << prompt;
		std::string line;
		std::getline(std::cin, line);

		auto tokens = Tokenize(line);
		if (tokens.empty()) {
			std::cout << "[!] Enter 'all' or a list of ports, or type 'cancel'.\n";
			continue;
		}

		if (tokens.size() == 1) {
			std::string lower = ToLowerCopy(tokens[0]);
			if (lower == "cancel") {
				return PortPromptResult::Cancel;
			}
		}

		std::string error;
		if (ParseWhitelistPortTokens(tokens, request, error)) {
			return PortPromptResult::Success;
		}

		std::cout << "[!] " << error << "\n";
	}
}

int main() {
	PrintBanner();
	FirewallManager firewallManager;

	if (!firewallManager.Initialize()) {
		std::cerr << "[!] Failed to initialize firewall manager.\n";
		return 1;
	}

	std::cout << "[+] Firewall manager initialized successfully.\n";

	FirewallMode mode = PromptMode(firewallManager);

	while (true) {
		PrintMenu(mode);
		std::string choice;
		std::getline(std::cin, choice);

		if (choice == "1") {
			HandleAddIP(firewallManager, mode);
			continue;
		}

		if (choice == "2") {
			HandleRemoveIP(firewallManager, mode);
			continue;
		}

		if (choice == "3") {
			HandleIPsFromFile(firewallManager, mode);
			continue;
		}

		if (choice == "4") {
			if (mode == FirewallMode::Whitelist) {
				ManageWhitelistedIPs(firewallManager);
			} else {
				ManageBlockedIPs(firewallManager);
			}
			continue;
		}

		if (choice == "5") {
			ShowRules(firewallManager);
			continue;
		}

		if (choice == "6") {
			ClearAllRules(firewallManager, mode);
			continue;
		}

		if (choice == "7" || choice == "q" || choice == "Q") {
			std::cout << "[+] Exiting AppGate.\n";
			break;
		}

		std::cout << "[!] Invalid choice. Please try again.\n";
	}

	return 0;
}

void PrintBanner() {
	std::cout << "==============================\n";
	std::cout << "  AppGate IP Controller (WFP)\n";
	std::cout << "==============================\n";
}

FirewallMode PromptMode(FirewallManager& fm) {
	while (true) {
		std::cout << "\nSelect firewall mode:\n";
		std::cout << "1. Blacklist (block specific IPs)\n";
		std::cout << "2. Whitelist (block everything except explicitly allowed IPs/ports)\n";
		std::cout << "Choice: ";
		std::string choice;
		std::getline(std::cin, choice);

		if (choice == "1") {
			if (fm.IsWhitelistMode()) {
				fm.DisableWhitelistMode();
			}
			std::cout << "[+] Blacklist mode selected.\n";
			return FirewallMode::Blacklist;
		}

		if (choice == "2") {
			if (fm.EnableWhitelistMode()) {
				std::cout << "[+] Whitelist mode selected.\n";
				return FirewallMode::Whitelist;
			}
			std::cout << "[!] Could not enable whitelist mode. Resolve the issue and try again.\n";
			continue;
		}

		std::cout << "[!] Invalid choice. Please enter 1 or 2.\n";
	}
}

void PrintMenu(FirewallMode mode) {
	if (mode == FirewallMode::Whitelist) {
		std::cout << "\nCurrent mode: Whitelist (all ports blocked by default)\n";
		std::cout << "1. Whitelist IP Address\n";
		std::cout << "2. Remove Whitelisted IP\n";
		std::cout << "3. Load Whitelist from white.txt\n";
		std::cout << "4. Manage Whitelisted IPs\n";
		std::cout << "5. Show Rules\n";
		std::cout << "6. Clear Managed Rules\n";
		std::cout << "7. Exit\n";
	} else {
		std::cout << "\nCurrent mode: Blacklist\n";
		std::cout << "1. Block IP Address\n";
		std::cout << "2. Unblock IP Address\n";
		std::cout << "3. Load Block List from file\n";
		std::cout << "4. Manage Blocked IPs\n";
		std::cout << "5. Show Rules\n";
		std::cout << "6. Clear Managed Rules\n";
		std::cout << "7. Exit\n";
	}
	std::cout << "Choice: ";
}

void HandleAddIP(FirewallManager& fm, FirewallMode mode) {
	const char* prompt = mode == FirewallMode::Whitelist ? "Enter IP address to whitelist: "
														 : "Enter IP address to block: ";
	std::cout << prompt;
	std::string ip;
	std::getline(std::cin, ip);

	if (ip.empty()) {
		std::cout << "[!] IP address cannot be empty.\n";
		return;
	}

	bool success = false;
	if (mode == FirewallMode::Whitelist) {
		WhitelistPortsRequest request;
		PortPromptResult result = PromptWhitelistPorts(
			"Enter 'all' to allow the entire IP or list allowed ports (space-separated). Type 'cancel' to abort: ", request);
		if (result == PortPromptResult::Cancel) {
			std::cout << "[i] Whitelist request cancelled.\n";
			return;
		}

		success = request.allowAll ? fm.WhitelistIP(ip) : fm.WhitelistIP(ip, request.ports);
	} else {
		success = fm.BlockIP(ip);
	}

	if (success) {
		std::cout << (mode == FirewallMode::Whitelist ? "[+] Whitelisted IP: " : "[+] Blocked IP: ") << ip << "\n";
	} else {
		std::cout << (mode == FirewallMode::Whitelist ? "[!] Failed to whitelist IP: " : "[!] Failed to block IP: ")
			  << ip << "\n";
	}
}

void HandleRemoveIP(FirewallManager& fm, FirewallMode mode) {
	const char* prompt = mode == FirewallMode::Whitelist ? "Enter IP address to remove from whitelist: "
														 : "Enter IP address to unblock: ";
	std::cout << prompt;
	std::string ip;
	std::getline(std::cin, ip);

	if (ip.empty()) {
		std::cout << "[!] IP address cannot be empty.\n";
		return;
	}

	bool success = mode == FirewallMode::Whitelist ? fm.RemoveWhitelistedIP(ip) : fm.UnblockIP(ip);
	if (success) {
		std::cout << (mode == FirewallMode::Whitelist ? "[+] Removed whitelisted IP: " : "[+] Unblocked IP: ")
				  << ip << "\n";
	} else {
		std::cout << (mode == FirewallMode::Whitelist ? "[!] Failed to remove whitelisted IP: "
													  : "[!] Failed to unblock IP: ")
				  << ip << "\n";
	}
}

void HandleIPsFromFile(FirewallManager& fm, FirewallMode mode) {
	std::string filePath;
	if (mode == FirewallMode::Whitelist) {
		filePath = "white.txt";
		std::cout << "[i] Loading whitelist entries from " << filePath << "\n";
	} else {
		std::cout << "Enter path to block list file (default blockIPs.txt): ";
		std::getline(std::cin, filePath);
		if (filePath.empty()) {
			filePath = "blockIPs.txt";
		}
	}

	std::ifstream file(filePath);
	if (!file.is_open()) {
		std::cout << "[!] Could not open file: " << filePath << "\n";
		return;
	}

	std::string line;
	int successCount = 0;
	int failCount = 0;

	while (std::getline(file, line)) {
		if (line.empty() || line[0] == '#') {
			continue;
		}

		std::istringstream iss(line);
		std::string ip;
		if (!(iss >> ip)) {
			continue;
		}

		std::vector<std::string> tokens;
		std::string token;
		while (iss >> token) {
			tokens.push_back(token);
		}

		if (mode == FirewallMode::Whitelist) {
			if (tokens.empty()) {
				std::cout << "[!] Whitelist entry for " << ip << " must specify 'all' or a port list.\n";
				++failCount;
				continue;
			}

			WhitelistPortsRequest request;
			std::string error;
			if (!ParseWhitelistPortTokens(tokens, request, error)) {
				std::cout << "[!] " << error << " for IP " << ip << ".\n";
				++failCount;
				continue;
			}

			bool success = request.allowAll ? fm.WhitelistIP(ip) : fm.WhitelistIP(ip, request.ports);
			if (success) {
				++successCount;
			} else {
				++failCount;
			}
			continue;
		}

		if (tokens.empty()) {
			if (fm.BlockIP(ip)) {
				++successCount;
			} else {
				++failCount;
			}
			continue;
		}

		bool requestAll = false;
		for (const auto& t : tokens) {
			std::string lower = t;
			std::transform(lower.begin(), lower.end(), lower.begin(),
				[](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
			if (lower == "all" || lower == "any" || lower == "*") {
				requestAll = true;
				break;
			}
		}

		if (requestAll) {
			if (fm.BlockIP(ip)) {
				++successCount;
			} else {
				++failCount;
			}
			continue;
		}

		bool processedPort = false;
		for (const auto& portToken : tokens) {
			int value = 0;
			try {
				value = std::stoi(portToken);
			} catch (...) {
				std::cout << "[!] Invalid port '" << portToken << "' for IP " << ip << ".\n";
				++failCount;
				continue;
			}

			if (value <= 0 || value > 65535) {
				std::cout << "[!] Port out of range ('" << portToken << "') for IP " << ip << ".\n";
				++failCount;
				continue;
			}

			processedPort = true;
			if (fm.BlockIP(ip, static_cast<std::uint16_t>(value))) {
				++successCount;
			} else {
				++failCount;
			}
		}

		if (!processedPort) {
			std::cout << "[!] No valid ports specified for IP " << ip << ".\n";
		}
	}

	const char* action = mode == FirewallMode::Whitelist ? "whitelisted" : "block operations performed";
	std::cout << "[+] " << successCount << " " << action;
	if (failCount > 0) {
		std::cout << ", " << failCount << " failed";
	}
	std::cout << ".\n";
}

void ShowRules(FirewallManager& fm) {
	const auto rules = fm.ListRules();
	if (rules.empty()) {
		std::cout << "[+] No managed IP rules.\n";
		return;
	}

	std::cout << "\nManaged IP Rules:\n";
	std::cout << std::left << std::setw(6) << "#" << std::setw(20) << "IP Address" << std::setw(10) << "Type" << "Details\n";
	std::cout << std::string(50, '-') << "\n";

	for (const auto& rule : rules) {
		const char* typeLabel = rule.isWhitelist ? "Allow" : "Block";
		std::string details;
		if (rule.isWhitelist) {
			details = DescribeAllowedPorts(rule);
		} else {
			details = rule.allPorts ? "All ports" : DescribeBlockedPorts(rule);
		}

		std::cout << std::left << std::setw(6) << rule.serial
			  << std::setw(20) << rule.ipAddress
			  << std::setw(10) << typeLabel
			  << details << "\n";
	}
}

void ClearAllRules(FirewallManager& fm, FirewallMode mode) {
	fm.ClearRules();
	std::cout << "[+] Cleared managed rules.";
	if (mode == FirewallMode::Whitelist) {
		std::cout << " Default block filters remain active.";
	}
	std::cout << "\n";
}

std::string DescribeBlockedPorts(const RuleEntry& rule) {
	if (rule.allPorts) {
		return "All ports";
	}
	if (rule.portRules.empty()) {
		return "None";
	}

	std::ostringstream oss;
	bool first = true;
	for (const auto& portRule : rule.portRules) {
		if (!first) {
			oss << ' ';
		}
		oss << portRule.port;
		first = false;
	}
	return oss.str();
}

std::string DescribeAllowedPorts(const RuleEntry& rule) {
	if (rule.allPorts) {
		return "All ports";
	}
	if (rule.portRules.empty()) {
		return "None";
	}

	std::ostringstream oss;
	bool first = true;
	for (const auto& portRule : rule.portRules) {
		if (!first) {
			oss << ' ';
		}
		oss << portRule.port;
		first = false;
	}
	return oss.str();
}

void ManageBlockedIPs(FirewallManager& fm) {
	while (true) {
		auto allRules = fm.ListRules();
		std::vector<RuleEntry> blocked;
		blocked.reserve(allRules.size());
		for (const auto& rule : allRules) {
			if (!rule.isWhitelist) {
				blocked.push_back(rule);
			}
		}

		if (blocked.empty()) {
			std::cout << "[+] No blocked IPs to manage.\n";
			return;
		}

		std::cout << "\nBlocked IPs:\n";
		std::cout << std::left << std::setw(6) << "#" << std::setw(20) << "IP Address" << "Blocked Ports\n";
		std::cout << std::string(40, '-') << "\n";
		for (const auto& rule : blocked) {
			std::cout << std::left << std::setw(6) << rule.serial
			          << std::setw(20) << rule.ipAddress
			          << DescribeBlockedPorts(rule) << "\n";
		}

		std::cout << "Enter serial number or IP to edit (blank to return): ";
		std::string selection;
		std::getline(std::cin, selection);
		if (selection.empty()) {
			return;
		}

		std::string targetIp;
		bool found = false;

		try {
			int serial = std::stoi(selection);
			auto serialIt = std::find_if(blocked.begin(), blocked.end(),
				[&](const RuleEntry& rule) { return rule.serial == serial; });
			if (serialIt != blocked.end()) {
				targetIp = serialIt->ipAddress;
				found = true;
			}
		} catch (...) {
			// fall through to string match
		}

		if (!found) {
			auto ipIt = std::find_if(blocked.begin(), blocked.end(),
				[&](const RuleEntry& rule) { return rule.ipAddress == selection; });
			if (ipIt != blocked.end()) {
				targetIp = ipIt->ipAddress;
				found = true;
			}
		}

		if (!found) {
			std::cout << "[!] Could not find a blocked IP matching '" << selection << "'.\n";
			continue;
		}

		EditBlockedIP(fm, targetIp);
	}
}

void EditBlockedIP(FirewallManager& fm, const std::string& ipAddress) {
	while (true) {
		auto rules = fm.ListRules();
		auto it = std::find_if(rules.begin(), rules.end(),
			[&](const RuleEntry& rule) { return !rule.isWhitelist && rule.ipAddress == ipAddress; });
		if (it == rules.end()) {
			std::cout << "[!] IP " << ipAddress << " is no longer blocked.\n";
			return;
		}

		const RuleEntry& rule = *it;
		std::cout << "\nManaging IP: " << ipAddress << "\n";
		std::cout << "Current block configuration: " << DescribeBlockedPorts(rule) << "\n";
		std::cout << "1. Block all ports\n";
		std::cout << "2. Add blocked port(s)\n";
		std::cout << "3. Remove blocked port\n";
		std::cout << "4. Done\n";
		std::cout << "Choice: ";
		std::string choice;
		std::getline(std::cin, choice);

		if (choice.empty() || choice == "4") {
			return;
		}

		if (choice == "1") {
			fm.BlockIP(ipAddress);
			continue;
		}

		if (choice == "2") {
			std::cout << "Enter port numbers (space-separated, type 'all' for all ports): ";
			std::string portsLine;
			std::getline(std::cin, portsLine);
			if (portsLine.empty()) {
				continue;
			}

			std::istringstream iss(portsLine);
			std::string token;
			bool requestedAll = false;
			std::vector<std::uint16_t> ports;

			while (iss >> token) {
				std::string lower = token;
				std::transform(lower.begin(), lower.end(), lower.begin(),
					[](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
				if (lower == "all" || lower == "any" || lower == "*") {
					requestedAll = true;
					break;
				}

				int value = 0;
				try {
					value = std::stoi(token);
				} catch (...) {
					std::cout << "[!] Invalid port '" << token << "'.\n";
					continue;
				}

				if (value <= 0 || value > 65535) {
					std::cout << "[!] Port out of range ('" << token << "').\n";
					continue;
				}

				ports.push_back(static_cast<std::uint16_t>(value));
			}

			if (requestedAll) {
				fm.BlockIP(ipAddress);
				continue;
			}

			if (ports.empty()) {
				std::cout << "[!] No valid ports provided.\n";
				continue;
			}

			for (std::uint16_t portValue : ports) {
				fm.BlockIP(ipAddress, portValue);
			}
			continue;
		}

		if (choice == "3") {
			if (rule.allPorts) {
				std::cout << "[!] IP currently blocks all ports. Switch to specific ports before removing any.\n";
				continue;
			}

			if (rule.portRules.empty()) {
				std::cout << "[!] No specific ports to remove.\n";
				continue;
			}

			std::cout << "Blocked ports: " << DescribeBlockedPorts(rule) << "\n";
			std::cout << "Enter port to remove: ";
			std::string portInput;
			std::getline(std::cin, portInput);
			if (portInput.empty()) {
				continue;
			}

			int value = 0;
			try {
				value = std::stoi(portInput);
			} catch (...) {
				std::cout << "[!] Invalid port entry.\n";
				continue;
			}

			if (value <= 0 || value > 65535) {
				std::cout << "[!] Port out of range.\n";
				continue;
			}

			fm.RemovePortBlock(ipAddress, static_cast<std::uint16_t>(value));
			continue;
		}

		std::cout << "[!] Invalid choice.\n";
	}
}

void ManageWhitelistedIPs(FirewallManager& fm) {
	while (true) {
		auto allRules = fm.ListRules();
		std::vector<RuleEntry> allowed;
		allowed.reserve(allRules.size());
		for (const auto& rule : allRules) {
			if (rule.isWhitelist) {
				allowed.push_back(rule);
			}
		}

		if (allowed.empty()) {
			std::cout << "[+] No whitelisted IPs to manage.\n";
			return;
		}

		std::cout << "\nWhitelisted IPs:\n";
		std::cout << std::left << std::setw(6) << "#" << std::setw(20) << "IP Address" << "Allowed Ports\n";
		std::cout << std::string(40, '-') << "\n";
		for (const auto& rule : allowed) {
			std::cout << std::left << std::setw(6) << rule.serial
			          << std::setw(20) << rule.ipAddress
			          << DescribeAllowedPorts(rule) << "\n";
		}

		std::cout << "Enter serial number or IP to edit (blank to return): ";
		std::string selection;
		std::getline(std::cin, selection);
		if (selection.empty()) {
			return;
		}

		std::string targetIp;
		bool found = false;

		try {
			int serial = std::stoi(selection);
			auto serialIt = std::find_if(allowed.begin(), allowed.end(),
				[&](const RuleEntry& rule) { return rule.serial == serial; });
			if (serialIt != allowed.end()) {
				targetIp = serialIt->ipAddress;
				found = true;
			}
		} catch (...) {
			// fall through to string match
		}

		if (!found) {
			auto ipIt = std::find_if(allowed.begin(), allowed.end(),
				[&](const RuleEntry& rule) { return rule.ipAddress == selection; });
			if (ipIt != allowed.end()) {
				targetIp = ipIt->ipAddress;
				found = true;
			}
		}

		if (!found) {
			std::cout << "[!] Could not find a whitelisted IP matching '" << selection << "'.\n";
			continue;
		}

		EditWhitelistedIP(fm, targetIp);
	}
}

void EditWhitelistedIP(FirewallManager& fm, const std::string& ipAddress) {
	while (true) {
		auto rules = fm.ListRules();
		auto it = std::find_if(rules.begin(), rules.end(),
			[&](const RuleEntry& rule) { return rule.isWhitelist && rule.ipAddress == ipAddress; });
		if (it == rules.end()) {
			std::cout << "[!] IP " << ipAddress << " is no longer whitelisted.\n";
			return;
		}

		const RuleEntry& rule = *it;
		std::cout << "\nManaging IP: " << ipAddress << "\n";
		std::cout << "Current allow configuration: " << DescribeAllowedPorts(rule) << "\n";
		std::cout << "1. Allow all ports\n";
		std::cout << "2. Add allowed port(s)\n";
		std::cout << "3. Remove allowed port\n";
		std::cout << "4. Remove IP from whitelist\n";
		std::cout << "5. Done\n";
		std::cout << "Choice: ";
		std::string choice;
		std::getline(std::cin, choice);

		if (choice.empty() || choice == "5") {
			return;
		}

		if (choice == "1") {
			if (!fm.WhitelistIP(ipAddress)) {
				std::cout << "[!] Failed to allow all ports for IP " << ipAddress << ".\n";
			}
			continue;
		}

		if (choice == "2") {
			WhitelistPortsRequest request;
			PortPromptResult result = PromptWhitelistPorts(
				"Enter 'all' to allow the entire IP or list allowed ports (space-separated). Type 'cancel' to abort: ", request);
			if (result == PortPromptResult::Cancel) {
				continue;
			}

			if (request.allowAll) {
				if (!fm.WhitelistIP(ipAddress)) {
					std::cout << "[!] Failed to allow all ports for IP " << ipAddress << ".\n";
				}
				continue;
			}

			if (!fm.AllowPortsForIP(ipAddress, request.ports)) {
				std::cout << "[!] Failed to add allowed ports.\n";
			}
			continue;
		}

		if (choice == "3") {
			if (rule.allPorts) {
				std::cout << "[!] IP currently allows all ports. Switch to specific ports before removing any.\n";
				continue;
			}

			if (rule.portRules.empty()) {
				std::cout << "[!] No specific ports to remove.\n";
				continue;
			}

			std::cout << "Allowed ports: " << DescribeAllowedPorts(rule) << "\n";
			std::cout << "Enter port to remove: ";
			std::string portInput;
			std::getline(std::cin, portInput);
			if (portInput.empty()) {
				continue;
			}

			int value = 0;
			try {
				value = std::stoi(portInput);
			} catch (...) {
				std::cout << "[!] Invalid port entry.\n";
				continue;
			}

			if (value <= 0 || value > 65535) {
				std::cout << "[!] Port out of range.\n";
				continue;
			}

			if (!fm.RemoveWhitelistPort(ipAddress, static_cast<std::uint16_t>(value))) {
				std::cout << "[!] Failed to remove allowed port.\n";
			}
			continue;
		}

		if (choice == "4") {
			if (fm.RemoveWhitelistedIP(ipAddress)) {
				std::cout << "[+] Removed IP " << ipAddress << " from whitelist.\n";
				return;
			}
			std::cout << "[!] Failed to remove IP from whitelist.\n";
			continue;
		}

		std::cout << "[!] Invalid choice.\n";
	}
}
