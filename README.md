# AppGate – IP Firewall Orchestrator

AppGate is a Windows command-line firewall assistant built on the Windows Filtering Platform (WFP). It lets you block or whitelist IPv4/IPv6 endpoints, optionally narrowing the scope to individual TCP/UDP ports. The tool runs entirely in the console, exposes both blacklist and whitelist workflows, and installs only in-memory (dynamic) WFP state so all filters vanish when AppGate exits.

## Highlights
- **Two enforcement modes** – traditional blacklist blocking or a whitelist “default deny” mode where all traffic is blocked unless explicitly opened.
- **IPv4 + IPv6** – every filter is installed for both protocol families and for inbound/outbound transport layers.
- **Per-port control** – block or allow the whole IP, or specify exact TCP/UDP ports (e.g., `443 8443`).
- **File-driven automation** – load `blockIPs.txt` or `white.txt` to bulk apply rules, including per-port entries.
- **Interactive management** – inspect managed rules, edit an existing IP, switch between “all ports” and “selected ports”, or remove individual port allowances.
- **Safe by default** – whitelist mode automatically installs blanket block filters before any IP is opened, ensuring no traffic slips through.

Supported OS: Windows 10/11 x64 · Toolchain: MSVC, CMake ≥ 3.15, Ninja or MSBuild

---

## Architecture in brief
- **Dynamic WFP session** – created at startup (`FWPM_SESSION_FLAG_DYNAMIC`) so filters are removed automatically on exit.
- **Custom sublayer** – isolates AppGate-managed filters from other firewall tooling.
- **Layers covered**:
  - Outbound: `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6`
  - Inbound: `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`, `FWPM_LAYER_INBOUND_TRANSPORT_V4/V6`
- **Whitelist default deny** – installs “block everything” filters first, then adds higher-weight permit filters for approved IP/port combinations.
- **Rule inventory** – `FirewallManager` tracks serial numbers, filter ids, and per-port state so the CLI can edit or remove rules safely.

---

## Prerequisites
- Windows 10/11 (x64) with administrator rights
- Visual Studio 2019 or 2022 (Desktop development with C++)
- Windows SDK (installed with VS)
- CMake 3.15+ and either Ninja or MSBuild
- Git (optional, for cloning the repo)

---

## Building AppGate
> Run these commands from a *Developer Command Prompt for VS* (x64) so MSVC and the Windows SDK are on `PATH`.

### Ninja (recommended)
```bat
git clone https://github.com/MAS191/AppGate.git
cd AppGate
cmake -S . -B build -G Ninja
cmake --build build
```

### Visual Studio generator
```bat
git clone https://github.com/MAS191/AppGate.git
cd AppGate
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Build output:
- Ninja: `build\AppGate.exe`
- MSBuild: `build\Release\AppGate.exe`

---

## Running (Administrator required)
WFP calls fail without elevation. Launch AppGate one of these ways:

```powershell
# From the build directory
Start-Process -FilePath .\AppGate.exe -Verb RunAs
```

or open a terminal as Administrator first, then execute `AppGate.exe` directly. If initialization prints `[!] Failed to initialize firewall manager`, the process is not elevated or the Base Filtering Engine (BFE) service is stopped.

---

## Modes & workflow

### Blacklist mode (default)
- Only the IPs you add are blocked.
- Blocking can target *all* ports or individual ports per IP.
- Useful for quickly cutting off abusive hosts while leaving the rest of the network untouched.

### Whitelist mode (default deny)
- AppGate first installs global block filters that drop every inbound/outbound connection.
- You must explicitly whitelist IPs and (optionally) ports before traffic flows.
- Choose between “allow all ports” or an exact port list for each address. The CLI enforces that selection when adding, editing, or importing entries.

Switch modes from the opening prompt. Leaving whitelist mode removes the default-deny filters and clears managed whitelist entries.

---

## CLI reference
Main menu options (labels differ slightly between modes):

1. **Whitelist/Block IP Address** – prompt for an IP, then choose `all` or specific ports to allow/block.
2. **Remove Whitelisted/Unblock IP** – delete an existing rule entirely.
3. **Load Whitelist / Load Block List** – import from a file (`white.txt` for whitelist mode or a custom path/default `blockIPs.txt` for blacklist mode).
4. **Manage Whitelisted/Blocked IPs** – open an editor for any managed IP to toggle “all ports”, add or remove specific ports, or delete the entry.
5. **Show Rules** – tabular view of every AppGate-managed rule with serial, IP, type, and details.
6. **Clear Managed Rules** – remove every rule AppGate created in the current session (whitelist mode keeps the background default-deny filters so the network stays blocked).
7. **Exit** – closes AppGate, automatically removing all dynamic filters.

### File formats
- **Blacklist** (`blockIPs.txt` by default): each line `IP [port ...]`. Use keywords `all`, `any`, or `*` to block every port.
- **Whitelist** (`white.txt`): each line must specify either `IP all` or `IP port1 port2 ...`. Invalid ports are rejected with a warning, and the line is skipped.
- Lines starting with `#` are treated as comments.

### Managing existing IPs
Use option 4 to pick an IP (by serial number or literal address). The editor lets you:
- Switch between “all ports” and per-port mode.
- Add allowed/blocked ports using the same token syntax as when adding a new IP.
- Remove an individual port allowance/block without deleting the whole entry.
- Remove the IP entirely from the current mode.

---

## Troubleshooting
- **Initialization failure** – verify you launched as Administrator and that the Windows “Base Filtering Engine” service is running.
- **Whitelist mode still allows traffic** – ensure you actually whitelisted the destination IP/port; any other traffic remains blocked by the default filters.
- **Cannot delete a filter** – rules are tracked by serial number; refresh with “Show Rules” to confirm the IP still exists before removing.
- **IPv6 formatting** – enter IPv6 addresses in standard notation (e.g., `2606:4700:4700::1111`). AppGate automatically picks the correct WFP layers.
- **Build errors** – confirm CMake is pointed at the VS generator that matches your installed toolset, and reinstall the Windows SDK if headers are missing.

---

## Project layout
- `main.cpp` – CLI menus, prompts, and file import/export logic.
- `FirewallManager.h/.cpp` – WFP session management plus block/whitelist filter orchestration.
- `Models.h` – rule/port metadata stored in memory for editing.
- `Utils.*` – helper utilities (string conversions, GUID helpers, etc.).
- `blockIPs.txt`, `white.txt` – sample lists for batch operations.
- `usage.md` – legacy/extended usage notes.

---

## License
AppGate is released under the MIT License – see `LICENSE` for the full text.

