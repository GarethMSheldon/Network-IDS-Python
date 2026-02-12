# Network IDS - Python Version
## Installation and Usage Guide

## Features

✅ Cross-platform network monitoring (Windows, Linux, macOS)
✅ Windows Event Log integration (4625, 4740, 1102, etc.)
✅ Real-time GUI with statistics dashboard
✅ Port scan detection
✅ Brute force login detection
✅ Suspicious port monitoring
✅ Export logs and reports
✅ Configurable detection thresholds

## Requirements

- Python 3.8 or higher
- Administrator/root privileges (for full functionality)
- Windows: For Event Log monitoring

## Installation

### Method 1: Using pip (Recommended)

```bash
# Install required packages
pip install -r requirements.txt
```

### Method 2: Manual installation

```bash
# Core dependency
pip install psutil

# Windows only (for Event Log monitoring)
pip install pywin32
```

### Method 3: Install as standalone

On Windows, you can create an executable:
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "NetworkIDS" network_ids.py
```

## Running the Application

### Windows

**Method 1: Run as Administrator**
1. Right-click on `network_ids.py`
2. Select "Run as administrator"
3. Or open PowerShell/Command Prompt as Administrator:
   ```cmd
   python network_ids.py
   ```

**Method 2: Create shortcut**
1. Right-click on `network_ids.py` → Send to → Desktop (create shortcut)
2. Right-click shortcut → Properties
3. Click "Advanced" → Check "Run as administrator"
4. Apply and OK

### Linux

```bash
# Run with sudo for full network monitoring
sudo python3 network_ids.py
```

### macOS

```bash
# Run with sudo
sudo python3 network_ids.py
```

## Usage Guide

### Starting Monitoring

1. Launch the application
2. Click "Start Monitoring" button
3. The status indicator will turn green
4. Statistics will begin updating every 2 seconds

### Understanding the Dashboard

**Statistics Cards:**
- **Connections**: Total network connections monitored
- **Unique IPs**: Number of different remote IP addresses
- **Net Alerts**: Alerts from network traffic analysis
- **Event Alerts**: Alerts from Windows Event Logs (Windows only)
- **Runtime**: How long monitoring has been active
- **Top Port**: Most frequently accessed port

**Alert Severity Levels:**
- 🔴 **HIGH**: Critical security events (brute force, port scans, audit log cleared)
- 🟠 **MEDIUM**: Suspicious activity (suspicious ports, account changes)
- 🟢 **LOW**: Informational events

### Alert Types

**Network Alerts:**
- **Port Scan**: Same IP accessing 10+ different ports
- **Suspicious Port**: Connection to known malicious ports (23, 445, 3389, etc.)
- **Data Exfiltration**: Simulated large data transfer detection

**Event Log Alerts (Windows only):**
- **Brute Force Login**: 5+ failed login attempts (Event ID 4625)
- **Account Locked Out**: Account lockout event (Event ID 4740)
- **Audit Log Cleared**: Security log cleared (Event ID 1102)
- **User Account Created**: New user created (Event ID 4720)
- **User Account Deleted**: User deleted (Event ID 4726)
- **Security Group Modified**: Group membership changed (Event ID 4732)
- **Audit Policy Changed**: System audit policy modified (Event ID 4719)

### Configuring Settings

1. Click the "Settings" button
2. Adjust thresholds:
   - **Port Scan Threshold**: Number of ports before alerting (default: 10)
   - **Brute Force Threshold**: Failed attempts before alerting (default: 5)
   - **Failed Logon Threshold**: Event log threshold (default: 5)
3. Click "Save Settings"

### Exporting Logs

1. Click "Export Logs" button
2. A report will be generated with:
   - Summary statistics
   - Network activity breakdown
   - Recent alerts
   - Log file locations
3. Report is automatically opened after export

### Clearing Alerts

Click "Clear Alerts" to remove all alerts from the display (logs are preserved)

## Testing the IDS

### Test Network Detection

```python
# Open Python and run:
import socket
import time

# Generate connections to suspicious ports
for port in [23, 445, 3389, 4444, 5900]:
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect(('scanme.nmap.org', port))
        sock.close()
    except:
        pass
    time.sleep(0.5)
```

### Test Failed Logon Detection (Windows)

Use the PowerShell simulation script:
```powershell
# Run in PowerShell as Administrator
.\Simulate_FailedLogons.ps1
```

Or use the one-liner:
```powershell
1..6 | ForEach-Object {
    $pass = ConvertTo-SecureString "Wrong$_" -AsPlainText -Force
    $cred = New-Object PSCredential("TestUser", $pass)
    try { Start-Process cmd -Credential $cred } catch { }
}
```

## Log Files

Logs are stored in:
- **Windows**: `%TEMP%\Enhanced_IDS_Logs\`
- **Linux/macOS**: `/tmp/Enhanced_IDS_Logs/`

**Log Types:**
- `IDS_YYYYMMDD_HHMMSS.log` - Main activity log
- `IDS_Alerts_YYYYMMDD_HHMMSS.log` - Alert-only log
- `IDS_Export_YYYYMMDD_HHMMSS.txt` - Exported reports

## Platform-Specific Notes

### Windows
- Full Event Log monitoring available
- Requires Administrator privileges
- Monitors Security Event Log
- Best performance and feature set

### Linux
- Network monitoring only
- Requires root/sudo
- No Event Log monitoring (uses syslog alternatively if needed)
- Can monitor network interfaces

### macOS
- Network monitoring only
- Requires sudo
- Limited system event monitoring
- Works best for network traffic analysis

## Troubleshooting

### "Permission Denied" Error
- Ensure running as Administrator (Windows) or with sudo (Linux/macOS)
- Check antivirus isn't blocking the application

### No Event Log Alerts (Windows)
1. Verify running as Administrator
2. Check Event Viewer → Windows Logs → Security for Event ID 4625
3. Enable audit logging:
   ```cmd
   auditpol /set /subcategory:"Logon" /failure:enable
   ```

### "Module not found: win32evtlog"
```bash
pip install pywin32
# If error persists:
python Scripts/pywin32_postinstall.py -install
```

### GUI Not Displaying
- Ensure tkinter is installed:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install python3-tk
  
  # Fedora
  sudo dnf install python3-tkinter
  
  # macOS (via Homebrew)
  brew install python-tk
  ```

### High CPU Usage
- Increase monitoring interval in code (change `time.sleep(2)` to higher value)
- Reduce number of connections checked
- Lower statistics update frequency

## Performance Tuning

Edit these values in `network_ids.py`:

```python
# Monitoring loop interval (seconds)
time.sleep(2)  # Change to 5 for less frequent checks

# Event check interval (seconds)
event_check_interval = 10  # Change to 30 for less frequent event checks

# Maximum events to check
max_events = 100  # Reduce to 50 for better performance
```

## Advanced Configuration

### Custom Suspicious Ports

Edit the `signature_rules` dictionary:
```python
'suspicious_ports': {
    'ports': [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 8080, 8888],
    'description': 'Connection to known suspicious ports'
}
```

### Custom Event IDs to Monitor

Edit the `event_signatures` dictionary:
```python
self.event_signatures = {
    4625: 'Failed logon attempt',
    4740: 'Account locked out',
    # Add your custom event IDs here
    4648: 'Logon using explicit credentials',
    4776: 'Computer attempted to validate credentials'
}
```

## Integration with SIEM

Export logs can be parsed by SIEM tools:

```python
# Example: Send alerts to syslog
import syslog
syslog.syslog(syslog.LOG_ALERT, f"IDS Alert: {alert_type} - {details}")
```

## API Usage (For Developers)

```python
from network_ids import NetworkIDS

# Create instance
ids = NetworkIDS()

# Programmatically add custom detection
def custom_check():
    # Your custom detection logic
    if suspicious_condition:
        ids.add_alert(
            'Custom Alert',
            'target',
            'details',
            'HIGH',
            'Custom'
        )

# Add to monitoring loop
# (Modify monitoring_loop method)
```

## Comparison with PowerShell Version

| Feature | PowerShell | Python |
|---------|-----------|--------|
| Network Monitoring | ✅ | ✅ |
| Event Log Monitoring | ✅ | ✅ (Windows only) |
| Cross-Platform | ❌ Windows only | ✅ Win/Linux/macOS |
| GUI Framework | WinForms | Tkinter |
| Performance | Good | Good |
| Dependencies | None (built-in) | psutil, pywin32 |
| Executable Creation | Harder | Easy (PyInstaller) |
| Code Readability | PowerShell syntax | Python (more universal) |

## Security Considerations

⚠️ **Important Security Notes:**

1. **Run with Least Privilege**: Only run as admin when necessary
2. **Log File Security**: Logs may contain sensitive information
3. **Network Exposure**: Does not open any network ports
4. **Event Log Access**: Requires admin to read Security log
5. **False Positives**: Tune thresholds to reduce false alerts

## License

MIT License - Use freely for educational and commercial purposes

## Support

For issues or questions:
- Check the troubleshooting section
- Review log files in the log directory
- Verify running with proper privileges

## Future Enhancements

Planned features:
- [ ] Email/SMS alerts
- [ ] Database storage for alerts
- [ ] Machine learning-based anomaly detection
- [ ] REST API for remote monitoring
- [ ] Docker container deployment
- [ ] Distributed monitoring across multiple hosts

## Credits

Based on the PowerShell Network IDS Enhanced version
Converted to Python for cross-platform compatibility
