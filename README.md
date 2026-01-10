# 🛡️ Network Intrusion Detection System (GUI)

A real-time, signature-based **Network Intrusion Detection System (IDS)** built in **PowerShell** with a modern graphical user interface. Monitors TCP connections on Windows systems and alerts on suspicious activity such as port scans, brute-force attempts, and traffic to known malicious ports.

> ⚠️ **For educational and defensive cybersecurity use only.** Not a replacement for enterprise-grade NIDS like Suricata or Zeek.

---

## ✨ Features

- **Real-time monitoring** of established & listening TCP connections
- **Signature-based detection** for:
  - Port scanning (threshold-based)
  - Connections to suspicious ports (e.g., 4444, 3389, 135)
- **Live statistics dashboard**:
  - Total connections, unique IPs, top ports
  - Connection rate (per minute)
  - Runtime counter
- **Alert logging** with severity levels (HIGH/MEDIUM/LOW)
- **Exportable reports** and persistent log files
- **Dark-themed terminal-style activity log**
- Runs entirely in-memory (no external dependencies)

---

## 🖥️ Requirements

- **Windows 10/11 or Windows Server 2016+**
- **PowerShell 5.1 or later**
- **Administrator privileges** (required to access network connection data)

> 💡 The script includes `#Requires -RunAsAdministrator` — it will not run without elevated rights.

---

## ▶️ Quick Start

1. **Clone or download** this repository.
2. Open **PowerShell as Administrator**.
3. Navigate to the project folder:
   ```powershell
   cd path\to\network-ids-gui
