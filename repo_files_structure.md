# Windows IDS Tool - Complete Repository Structure

## 📂 Repository Files

Here's the complete file structure for your GitHub repository:

```
Windows-IDS-Tool/
│
├── Windows-IDS-Tool.ps1          # Main application script
├── README.md                      # Repository documentation
├── LICENSE                        # MIT License file
├── .gitignore                     # Git ignore rules
├── CONTRIBUTING.md                # Contribution guidelines
├── CHANGELOG.md                   # Version history
│
├── docs/                          # Documentation folder
│   ├── INSTALLATION.md           # Detailed installation guide
│   ├── USAGE.md                  # Usage examples and tutorials
│   ├── CONFIGURATION.md          # Configuration options
│   └── SCREENSHOTS.md            # Application screenshots
│
├── examples/                      # Example configurations
│   ├── custom-rules.ps1          # Custom detection rules example
│   └── high-security-config.ps1  # High security configuration
│
└── scripts/                       # Utility scripts
    ├── install.ps1               # Installation helper
    └── uninstall.ps1             # Cleanup script
```

---

## 📄 File Contents

### 1. `.gitignore`

```gitignore
# Log files
*.log
IDS_Logs/
*.txt

# PowerShell
*.ps1xml
*.psc1
*.psm1_*

# Temporary files
*.tmp
*.temp
~$*

# System files
Thumbs.db
.DS_Store
desktop.ini

# User-specific files
*.user
*.suo
*.cache

# Backup files
*.bak
*.backup
```

---

### 2. `LICENSE` (MIT License)

```text
MIT License

Copyright (c) 2026 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### 3. `CONTRIBUTING.md`

```markdown
# Contributing to Windows IDS Tool

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. Create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (Windows version, PowerShell version)
   - Screenshots if applicable

### Suggesting Features

1. Check existing feature requests
2. Create an issue with:
   - Clear description of the feature
   - Use cases and benefits
   - Potential implementation approach

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/YourFeature`
3. Make your changes
4. Test thoroughly
5. Update documentation
6. Commit with clear messages: `git commit -m "Add feature: description"`
7. Push to your fork: `git push origin feature/YourFeature`
8. Open a Pull Request

## Code Style Guidelines

- Use 4 spaces for indentation
- Follow PowerShell naming conventions
- Add comments for complex logic
- Keep functions focused and modular
- Test on multiple Windows versions

## Testing

Before submitting:
- Test on Windows 10 and Windows 11
- Verify all GUI elements work correctly
- Check alert generation with various scenarios
- Ensure logs are created properly
- Test with both normal and elevated privileges

## Questions?

Feel free to open an issue for any questions or clarifications.
```

---

### 4. `CHANGELOG.md`

```markdown
# Changelog

All notable changes to Windows IDS Tool will be documented in this file.

## [1.0.0] - 2026-01-10

### Added
- Initial release
- Real-time network monitoring with GUI
- Signature-based detection for suspicious ports
- Anomaly-based detection for port scans
- Connection rate monitoring
- Alert system with severity levels
- Statistics dashboard
- Activity logging system
- Export functionality for reports
- Color-coded alert display

### Features
- Monitors TCP connections in real-time
- Detects port scanning attempts
- Identifies connections to high-risk ports
- Tracks unique IP addresses
- Generates comprehensive logs
- Provides visual statistics

### Supported Platforms
- Windows 10 (1809+)
- Windows 11
- Windows Server 2016+
- PowerShell 5.1+

## [Unreleased]

### Planned Features
- Machine learning anomaly detection
- Protocol-specific analysis (HTTP, DNS)
- IP whitelist/blacklist management
- Email alerting
- SIEM integration
- Enhanced visualizations
```

---

### 5. `docs/INSTALLATION.md`

```markdown
# Installation Guide

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10 (version 1809 or later) or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **RAM**: 2 GB
- **Storage**: 100 MB free space
- **Permissions**: Administrator access

### Recommended Requirements
- **Operating System**: Windows 11 or Windows Server 2022
- **PowerShell**: Version 7.x
- **RAM**: 4 GB or more
- **Network**: Active network adapter

## Installation Steps

### Method 1: Git Clone (Recommended)

1. Open PowerShell as Administrator
2. Navigate to your desired directory:
   ```powershell
   cd C:\Tools
   ```
3. Clone the repository:
   ```powershell
   git clone https://github.com/yourusername/Windows-IDS-Tool.git
   ```
4. Navigate to the directory:
   ```powershell
   cd Windows-IDS-Tool
   ```
5. Run the tool:
   ```powershell
   .\Windows-IDS-Tool.ps1
   ```

### Method 2: Manual Download

1. Download the latest release from GitHub
2. Extract the ZIP file to your preferred location
3. Right-click on `Windows-IDS-Tool.ps1`
4. Select "Run with PowerShell" (as Administrator)

### Method 3: Using Installation Script

1. Download the repository
2. Run the installation script:
   ```powershell
   .\scripts\install.ps1
   ```
3. Follow the on-screen prompts

## Execution Policy

If you encounter execution policy errors:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or run with bypass:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\Windows-IDS-Tool.ps1
```

## Verification

To verify installation:
1. Check PowerShell version: `$PSVersionTable`
2. Verify administrator privileges: `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`
3. Test network cmdlet: `Get-NetTCPConnection | Select-Object -First 1`

## Troubleshooting

### "Script cannot be loaded because running scripts is disabled"
- Run: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

### "Access is denied"
- Ensure PowerShell is running as Administrator
- Check User Account Control (UAC) settings

### "Get-NetTCPConnection not recognized"
- Update Windows Management Framework
- Install PowerShell 5.1 or higher

## Uninstallation

Run the uninstall script:
```powershell
.\scripts\uninstall.ps1
```

Or manually:
1. Delete the program folder
2. Remove log files from `%TEMP%\IDS_Logs\`
```

---

### 6. `scripts/install.ps1`

```powershell
# Windows IDS Tool Installation Script
#Requires -RunAsAdministrator

Write-Host "=== Windows IDS Tool Installation ===" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "Checking PowerShell version... " -NoNewline
if ($psVersion.Major -ge 5) {
    Write-Host "OK ($($psVersion.ToString()))" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "PowerShell 5.1 or higher required. Current version: $($psVersion.ToString())"
    exit 1
}

# Check for Administrator privileges
Write-Host "Checking administrator privileges... " -NoNewline
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "Please run this script as Administrator"
    exit 1
}

# Create log directory
$logPath = "$env:TEMP\IDS_Logs"
Write-Host "Creating log directory... " -NoNewline
if (!(Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "Already exists" -ForegroundColor Yellow
}

# Test network capabilities
Write-Host "Testing network monitoring capabilities... " -NoNewline
try {
    Get-NetTCPConnection -State Established -ErrorAction Stop | Select-Object -First 1 | Out-Null
    Write-Host "OK" -ForegroundColor Green
} catch {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "Network monitoring cmdlets not available"
    exit 1
}

# Create desktop shortcut (optional)
Write-Host ""
$createShortcut = Read-Host "Create desktop shortcut? (Y/N)"
if ($createShortcut -eq 'Y' -or $createShortcut -eq 'y') {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Windows IDS Tool.lnk")
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$PSScriptRoot\..\Windows-IDS-Tool.ps1`""
    $Shortcut.WorkingDirectory = Split-Path $PSScriptRoot -Parent
    $Shortcut.IconLocation = "shell32.dll,48"
    $Shortcut.Description = "Network Intrusion Detection System"
    $Shortcut.Save()
    Write-Host "Desktop shortcut created" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "To run the tool:"
Write-Host "  .\Windows-IDS-Tool.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Logs will be saved to:" -ForegroundColor Yellow
Write-Host "  $logPath" -ForegroundColor Gray
Write-Host ""
```

---

### 7. `scripts/uninstall.ps1`

```powershell
# Windows IDS Tool Uninstall Script
#Requires -RunAsAdministrator

Write-Host "=== Windows IDS Tool Uninstallation ===" -ForegroundColor Yellow
Write-Host ""

# Remove log directory
$logPath = "$env:TEMP\IDS_Logs"
Write-Host "Checking for log files... " -NoNewline
if (Test-Path $logPath) {
    $confirm = Read-Host "Delete all log files in $logPath? (Y/N)"
    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        Remove-Item -Path $logPath -Recurse -Force
        Write-Host "Log files removed" -ForegroundColor Green
    } else {
        Write-Host "Log files preserved" -ForegroundColor Yellow
    }
} else {
    Write-Host "No log files found" -ForegroundColor Gray
}

# Remove desktop shortcut
$shortcut = "$env:USERPROFILE\Desktop\Windows IDS Tool.lnk"
Write-Host "Checking for desktop shortcut... " -NoNewline
if (Test-Path $shortcut) {
    Remove-Item -Path $shortcut -Force
    Write-Host "Shortcut removed" -ForegroundColor Green
} else {
    Write-Host "No shortcut found" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== Uninstallation Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "You can safely delete the program folder." -ForegroundColor Cyan
Write-Host ""
```

---

`network-monitoring`
