# Network Intrusion Detection System (GUI) - Python Edition

A real-time, signature-based Network Intrusion Detection System (IDS) built in Python with a modern graphical user interface. Monitors network connections on Windows and Linux systems, and on Windows additionally monitors Security Event Logs for suspicious activity such as port scans, brute-force login attempts, and connections to known malicious ports.

**For educational and defensive cybersecurity use only.** Not a replacement for enterprise-grade NIDS like Suricata or Zeek. Always obtain proper authorization before monitoring any network or system.

## Features

* Real-time monitoring of established network connections (TCP/UDP)
* **Windows-exclusive**: Security Event Log monitoring (Event IDs 4625, 4740, 1102, 4720, 4726, 4732, 4719)
* Signature-based detection for:
    * Port scanning (threshold-based detection of multiple ports from same source)
    * Brute-force login attempts (via failed logon events on Windows)
    * Connections to suspicious ports (e.g., 23, 135, 139, 445, 3389, 4444, 5900)
* Live statistics dashboard:
    * Total connections, unique IPs, top active port
    * Separate counters for network and event log alerts
    * Runtime counter with real-time updates
* Color-coded security alerts with severity levels (HIGH/MEDIUM/LOW)
* Terminal-style activity log for system events and monitoring status
* Exportable monitoring reports with comprehensive statistics
* Persistent log files for forensic analysis
* Configurable detection thresholds via intuitive Settings dialog

## Requirements

### Platform Support

* **Windows**: Windows 10/11 or Windows Server 2016+ (for full functionality including Event Log monitoring)
* **Linux**: Ubuntu/Debian, RHEL, CentOS, or other systemd-based distributions (network monitoring only)

### Software Requirements

* Python 3.8 or later
* Required packages:
    * psutil (cross-platform process and system monitoring)
    * tkinter (included with standard Python installations)
    * **Windows only**: pywin32 (for Event Log access)

### Privileges

* **Windows**: Administrator privileges required for Event Log access and comprehensive network monitoring
* **Linux**: Root privileges recommended for full network visibility (basic monitoring may work without elevated privileges)

## Installation

### Windows Setup

1. Install Python 3.8+ from https://www.python.org/downloads/ (ensure "Add Python to PATH" is checked during installation)
2. Install required packages:

```powershell
pip install psutil pywin32
```

3. Run the pywin32 post-install script as Administrator:

```powershell
python Scripts/pywin32_postinstall.py -install
```

### Linux Setup (Debian/Ubuntu)

1. Install Python and dependencies:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk
```

2. Install required packages:

```bash
pip3 install psutil
```

### Linux Setup (RHEL/CentOS)

```bash
sudo yum install python3 python3-tkinter
pip3 install psutil
```

## Usage

### Starting the Application

Windows (PowerShell as Administrator):

```powershell
python network_ids.py
```

Linux (terminal with sudo):

```bash
sudo python3 network_ids.py
```

**Important**: On Windows, the application will warn you if not running with administrator privileges. Event Log monitoring will be disabled without elevation.

### GUI Workflow

* Upon launch, the dashboard shows "STATUS: STOPPED" with a red indicator
* Click "Start Monitoring" to begin surveillance:
    * Network connections are analyzed every 2 seconds
    * Windows Event Logs are checked every 10 seconds (Windows only)
    * Statistics update in real-time on the dashboard
* Alerts appear in the top panel with color coding:
    * RED = HIGH severity (port scans, audit log cleared)
    * ORANGE = MEDIUM severity (suspicious ports, account changes)
    * GREEN = LOW severity (informational events)
* Use "Settings" to adjust detection sensitivity:
    * Port scan threshold (default: 10 ports)
    * Brute-force attempt threshold (default: 5 attempts)
    * Failed logon threshold (default: 5 attempts within 5 minutes)
* Click "Export Logs" to generate a comprehensive report of the monitoring session
* Click "Stop Monitoring" to halt surveillance when finished

### Log Files Location

All activity is automatically logged to:

* Windows: %TEMP%\Enhanced_IDS_Logs\
* Linux: /tmp/Enhanced_IDS_Logs/

Files include:

* IDS_YYYYMMDD_HHMMSS.log - Complete system activity log
* IDS_Alerts_YYYYMMDD_HHMMSS.log - Alert-specific entries only
* Exported reports when using the "Export Logs" feature

## Platform-Specific Notes

### Windows

* Full functionality requires administrator privileges
* Monitors both network connections AND Security Event Logs
* Event Log monitoring covers critical security events:
    * Failed logons (Event ID 4625)
    * Account lockouts (4740)
    * Security policy changes (4719)
    * Audit log clearing (1102)
    * User account modifications (4720/4726)

### Linux

* Event Log monitoring is unavailable (Windows-only feature)
* Network monitoring works with standard privileges but may have limited visibility
* For complete network visibility, run with root privileges:
```bash
sudo python3 network_ids.py
```
* Focuses exclusively on connection analysis and port activity

## Security Considerations

* This tool generates alerts based on signatures and thresholds - not all alerts indicate actual compromise
* False positives may occur from legitimate administrative tools, vulnerability scanners, or backup systems
* Always investigate alerts in context with other security data
* Never deploy monitoring tools on systems without explicit authorization
* Logs contain sensitive information - protect exported reports appropriately
* Not designed to detect encrypted threats or advanced persistent threats (APTs)

## License

This software is provided for educational and defensive security purposes only. No warranty is expressed or implied. Use at your own risk in compliance with all applicable laws and organizational policies.
