# 🌐 Dynamic TOR Traffic Interceptor (v1.0.0)

**A cross-platform utility written in C that transparently routes the network traffic of a single, specified process through the TOR network, ensuring privacy and anonymity.**

---

## ✨ Features

This project leverages dynamic linking mechanisms (**DLL injection** on Windows and **LD_PRELOAD** on Linux) to intercept and proxy standard socket operations (`connect`, `send`, `recv`, etc.) from a target application through a local SOCKS4 proxy (TOR).

| Feature | Description |
| :--- | :--- |
| **Platform Compatibility** | Supports **Windows (.dll)** and **Linux (.so)** dynamic linking environments. |
| **Process-Specific Routing** | Only the targeted command/process traffic is affected, leaving the rest of the system untouched. |
| **Mandatory DNS Interception** | **Custom client-side DNS resolution** is implemented to force all DNS queries through the SOCKS4 proxy, preventing common DNS leaks that would otherwise defeat the purpose of using TOR. |
| **Clean Exit** | Traffic rerouting is temporary and ends when the linked process terminates. |

---

## 🛠️ Usage

### **Prerequisites**

You must have the **TOR Browser** or a standalone **TOR service** running locally. This utility requires the TOR SOCKS4 proxy to be listening on the default port: `127.0.0.1:9050`.

### **Linux (Shared Object - `.so`)**

On Linux, this utility uses the `LD_PRELOAD` environment variable to load the shared object before the target program starts.

1.  Compile the project to generate the shared object.
2.  Preload the library and run the command:

This is a proof-of-concept (v1.0.0). Potential directions for future development include:

GUI Interface: Develop a graphical user interface using [Qt/GTK/Electron] to simplify the injection process, especially for Windows users.

System-wide Service: Refactor the utility to run as a daemon/service that manages traffic redirection system-wide (e.g., via firewall rules or VPN integration) rather than on a per-process basis.

Configuration File: Implement a configuration file to easily change the SOCKS5 proxy address/port and manage whitelisting/blacklisting of target applications.
