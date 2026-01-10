#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enhanced Network Intrusion Detection System with GUI interface
.DESCRIPTION
    Monitors network traffic for suspicious patterns and potential threats
    with a professional GUI interface and comprehensive logging.
.NOTES
    File Name      : NetworkIDS.ps1
    Author         : Security Team
    Prerequisite   : PowerShell 5.1+ running as Administrator
    Copyright 2026 - Enhanced Security Solutions
#>

# Error handling preferences
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

try {
    # Load required assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    # Create log directory with error handling
    $LogPath = "$env:TEMP\Enhanced_IDS_Logs"
    try {
        if (!(Test-Path $LogPath -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to create log directory: $_. Please ensure you have proper permissions.",
            "Directory Creation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        exit 1
    }

    # Generate log file paths
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $LogFile = Join-Path $LogPath "IDS_$timestamp.log"
    $AlertFile = Join-Path $LogPath "IDS_Alerts_$timestamp.log"

    # Signature-based detection rules
    $SignatureRules = @{
        "Port Scan" = @{
            Pattern = "Multiple connections to different ports from same source"
            Threshold = 10
        }
        "Brute Force" = @{
            Pattern = "Multiple failed authentication attempts"
            Threshold = 5
        }
        "Suspicious Ports" = @{
            Ports = @(23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 8080)
        }
        "Data Exfiltration" = @{
            Pattern = "Unusually large data transfer to external IP"
            Threshold = 100MB
        }
    }

    # Statistics tracking
    $Script:Stats = @{
        TotalConnections = 0
        UniqueIPs = @{}
        PortActivity = @{}
        Alerts = @()
        StartTime = Get-Date
        IsMonitoring = $false
        ConnectionHistory = New-Object System.Collections.Queue
    }

    # Create main form with proper disposal
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Network Intrusion Detection System"
    $form.Size = New-Object System.Drawing.Size(1100, 750)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::White
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $form.MinimumSize = New-Object System.Drawing.Size(900, 600)
    
    # Ensure proper cleanup when form closes
    $form.Add_FormClosing({
        param($sender, $e)
        if ($script:timer) {
            $script:timer.Stop()
            $script:timer.Dispose()
        }
    })

    # Header Panel
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Dock = "Top"
    $headerPanel.Height = 80
    $headerPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 60, 125)
    $form.Controls.Add($headerPanel)

    # Logo and title
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "NETWORK INTRUSION DETECTION SYSTEM"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = [System.Drawing.Color]::White
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.AutoSize = $true
    $headerPanel.Controls.Add($titleLabel)

    # Status indicator
    $statusPanel = New-Object System.Windows.Forms.Panel
    $statusPanel.Location = New-Object System.Drawing.Point(800, 25)
    $statusPanel.Size = New-Object System.Drawing.Size(250, 30)
    $statusPanel.BackColor = [System.Drawing.Color]::Transparent
    $headerPanel.Controls.Add($statusPanel)

    $statusIndicator = New-Object System.Windows.Forms.Panel
    $statusIndicator.Size = New-Object System.Drawing.Size(15, 15)
    $statusIndicator.BackColor = [System.Drawing.Color]::Red
    $statusIndicator.Location = New-Object System.Drawing.Point(0, 7)
    $statusIndicator.BorderStyle = "FixedSingle"
    $statusIndicator.Tag = "stopped"
    $statusPanel.Controls.Add($statusIndicator)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = " STATUS: STOPPED"
    $statusLabel.Location = New-Object System.Drawing.Point(20, 5)
    $statusLabel.Size = New-Object System.Drawing.Size(200, 20)
    $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $statusLabel.ForeColor = [System.Drawing.Color]::White
    $statusPanel.Controls.Add($statusLabel)

    # Stats Panel with cards
    $statsPanel = New-Object System.Windows.Forms.Panel
    $statsPanel.Dock = "Top"
    $statsPanel.Height = 140
    $statsPanel.BackColor = [System.Drawing.Color]::White
    $statsPanel.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $form.Controls.Add($statsPanel)

    # Create stats cards
    $cardWidth = 170
    $cardHeight = 80
    $cardSpacing = 20
    $stats = @("Connections", "Unique IPs", "Alerts", "Runtime", "Conn/Min", "Top Port")

    try {
        for ($i = 0; $i -lt $stats.Count; $i++) {
            $xPos = $i * ($cardWidth + $cardSpacing) + 10
            
            $card = New-Object System.Windows.Forms.Panel
            $card.Size = New-Object System.Drawing.Size($cardWidth, $cardHeight)
            $card.Location = New-Object System.Drawing.Point($xPos, 10)
            $card.BackColor = [System.Drawing.Color]::White
            $card.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
            $card.Tag = $stats[$i]
            $statsPanel.Controls.Add($card)
            
            # Add Paint event handler
            $card.Add_Paint({
                param($sender, $e)
                $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 220, 220), 1)
                $e.Graphics.DrawRectangle($pen, 0, 0, $sender.Width - 1, $sender.Height - 1)
                $pen.Dispose()
            })
            
            # Card title
            $title = New-Object System.Windows.Forms.Label
            $title.Text = $stats[$i]
            $title.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $title.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
            $title.Location = New-Object System.Drawing.Point(15, 10)
            $title.AutoSize = $true
            $card.Controls.Add($title)
            
            # Card value
            $value = New-Object System.Windows.Forms.Label
            $value.Text = "0"
            $value.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
            $value.ForeColor = [System.Drawing.Color]::FromArgb(40, 40, 140)
            $value.Location = New-Object System.Drawing.Point(15, 35)
            $value.AutoSize = $true
            $card.Controls.Add($value)
            
            # Card icon (text-based to avoid encoding issues)
            $icon = New-Object System.Windows.Forms.Label
            $icon.Size = New-Object System.Drawing.Size(40, 40)
            $icon.Location = New-Object System.Drawing.Point(($cardWidth - 55), 20)
            $icon.TextAlign = "MiddleCenter"
            $icon.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
            $icon.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 200)
            
            switch ($stats[$i]) {
                "Connections" { $icon.Text = "C" }
                "Unique IPs" { $icon.Text = "IP" }
                "Alerts" { $icon.Text = "A"; $icon.ForeColor = [System.Drawing.Color]::Red }
                "Runtime" { $icon.Text = "T" }
                "Conn/Min" { $icon.Text = "R" }
                "Top Port" { $icon.Text = "P" }
            }
            
            $card.Controls.Add($icon)
        }
    }
    catch {
        Write-Error "Failed to create statistics cards: $_"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to create statistics cards: $_",
            "UI Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        exit 1
    }

    # Alert ListView
    $alertPanel = New-Object System.Windows.Forms.Panel
    $alertPanel.Dock = "Top"
    $alertPanel.Height = 340
    $form.Controls.Add($alertPanel)

    $alertLabel = New-Object System.Windows.Forms.Label
    $alertLabel.Text = "SECURITY ALERTS"
    $alertLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $alertLabel.ForeColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $alertLabel.Location = New-Object System.Drawing.Point(20, 10)
    $alertLabel.AutoSize = $true
    $alertPanel.Controls.Add($alertLabel)

    $alertListView = New-Object System.Windows.Forms.ListView
    $alertListView.Location = New-Object System.Drawing.Point(20, 40)
    $alertListView.Size = New-Object System.Drawing.Size(1050, 280)
    $alertListView.View = [System.Windows.Forms.View]::Details
    $alertListView.FullRowSelect = $true
    $alertListView.GridLines = $false
    $alertListView.BorderStyle = "FixedSingle"
    $alertListView.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $alertListView.ForeColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $alertListView.BackColor = [System.Drawing.Color]::White
    $alertListView.HeaderStyle = "Nonclickable"
    
    # Enable double buffering to prevent flickering
    try {
        $prop = $alertListView.GetType().GetProperty("DoubleBuffered", [System.Reflection.BindingFlags]"Instance,NonPublic")
        if ($prop) {
            $prop.SetValue($alertListView, $true, $null)
        }
    }
    catch {
        # Fallback if DoubleBuffered property can't be set
        Write-Verbose "Could not enable double buffering: $_"
    }
    
    $alertListView.Columns.Add("Time", 120) | Out-Null
    $alertListView.Columns.Add("Severity", 90) | Out-Null
    $alertListView.Columns.Add("Type", 150) | Out-Null
    $alertListView.Columns.Add("Source IP", 150) | Out-Null
    $alertListView.Columns.Add("Details", 500) | Out-Null
    $alertPanel.Controls.Add($alertListView)

    # Activity Log with terminal styling
    $activityPanel = New-Object System.Windows.Forms.Panel
    $activityPanel.Dock = "Fill"
    $activityPanel.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $form.Controls.Add($activityPanel)

    $logLabel = New-Object System.Windows.Forms.Label
    $logLabel.Text = "SYSTEM ACTIVITY LOG"
    $logLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $logLabel.ForeColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $logLabel.Location = New-Object System.Drawing.Point(10, 10)
    $logLabel.AutoSize = $true
    $activityPanel.Controls.Add($logLabel)

    $activityLog = New-Object System.Windows.Forms.RichTextBox
    $activityLog.Location = New-Object System.Drawing.Point(10, 40)
    $activityLog.Size = New-Object System.Drawing.Size(1050, 150)
    $activityLog.BorderStyle = "FixedSingle"
    $activityLog.ReadOnly = $true
    $activityLog.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
    $activityLog.ForeColor = [System.Drawing.Color]::FromArgb(0, 220, 0)
    $activityLog.Font = New-Object System.Drawing.Font("Consolas", 9)
    $activityLog.ScrollBars = "Vertical"
    $activityPanel.Controls.Add($activityLog)

    # Button Panel
    $btnPanel = New-Object System.Windows.Forms.Panel
    $btnPanel.Dock = "Bottom"
    $btnPanel.Height = 60
    $btnPanel.Padding = New-Object System.Windows.Forms.Padding(20, 0, 20, 0)
    $btnPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    $form.Controls.Add($btnPanel)

    # Create buttons without hover effect issues
    $buttonDefs = @(
        @{Text="Start Monitoring"; Tag="start"; BackColor=[System.Drawing.Color]::FromArgb(0, 150, 0)},
        @{Text="Stop Monitoring"; Tag="stop"; BackColor=[System.Drawing.Color]::FromArgb(180, 0, 0)},
        @{Text="Clear Alerts"; Tag="clear"; BackColor=[System.Drawing.Color]::FromArgb(100, 100, 100)},
        @{Text="Export Logs"; Tag="export"; BackColor=[System.Drawing.Color]::FromArgb(0, 100, 200)},
        @{Text="Settings"; Tag="settings"; BackColor=[System.Drawing.Color]::FromArgb(80, 80, 180)}
    )

    $btnSpacing = 15
    $btnWidth = 140
    $btnHeight = 40

    $script:buttons = @{}
    
    for ($i = 0; $i -lt $buttonDefs.Count; $i++) {
        $btnX = $i * ($btnWidth + $btnSpacing) + 20
        
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $buttonDefs[$i].Text
        $button.Tag = $buttonDefs[$i].Tag
        $button.Location = New-Object System.Drawing.Point($btnX, 10)
        $button.Size = New-Object System.Drawing.Size($btnWidth, $btnHeight)
        $button.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $button.ForeColor = [System.Drawing.Color]::White
        $button.BackColor = $buttonDefs[$i].BackColor
        $button.FlatStyle = "Flat"
        $button.FlatAppearance.BorderSize = 0
        $button.Cursor = [System.Windows.Forms.Cursors]::Hand
        
        # FIXED HOVER EFFECT CODE
        $baseColor = $buttonDefs[$i].BackColor
        $button.Add_MouseEnter({
            param($sender, $e)
            # Create hover color by lightening the base color
            $currentColor = $sender.BackColor
            $sender.BackColor = [System.Drawing.Color]::FromArgb(
                [Math]::Min(255, $currentColor.R + 30),
                [Math]::Min(255, $currentColor.G + 30),
                [Math]::Min(255, $currentColor.B + 30)
            )
        })
        
        $button.Add_MouseLeave({
            param($sender, $e)
            $sender.BackColor = $baseColor
        })
        
        $btnPanel.Controls.Add($button)
        $script:buttons[$buttonDefs[$i].Tag] = $button
    }

    # Set initial button states
    $script:buttons["stop"].Enabled = $false

    # Timer for monitoring
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 2000  # 2 seconds
    $script:timer = $timer

    # Functions with proper error handling
    function Write-IDSLog {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Message,
            
            [Parameter(Mandatory=$false)]
            [ValidateSet("INFO", "ALERT", "ERROR", "WARNING")]
            [string]$Level = "INFO"
        )
        
        try {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "[$timestamp] [$Level] $Message"
            
            # Write to main log file
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
            
            # Also write to alert log if it's an alert
            if ($Level -eq "ALERT") {
                Add-Content -Path $AlertFile -Value $logMessage -ErrorAction Stop
            }
            
            # Update activity log with proper thread handling
            if ($activityLog.InvokeRequired) {
                $activityLog.Invoke([System.Action]{
                    Update-ActivityLog -Message $Message -Level $Level
                })
            }
            else {
                Update-ActivityLog -Message $Message -Level $Level
            }
        }
        catch {
            # Fallback error handling - don't throw here as it could cause infinite loops
            try {
                $fallbackLog = "$env:TEMP\IDS_Fallback.log"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to write log: $_" | Out-File -FilePath $fallbackLog -Append -ErrorAction SilentlyContinue
            }
            catch {
                # Last resort - do nothing to prevent cascading failures
            }
        }
    }
    
    function Update-ActivityLog {
        param(
            [string]$Message,
            [string]$Level = "INFO"
        )
        
        $activityLog.SelectionStart = $activityLog.TextLength
        $activityLog.SelectionLength = 0
        
        switch ($Level) {
            "ALERT" {
                $activityLog.SelectionColor = [System.Drawing.Color]::Red
                $activityLog.AppendText("[!] ")
            }
            "ERROR" {
                $activityLog.SelectionColor = [System.Drawing.Color]::Red
                $activityLog.AppendText("[E] ")
            }
            "WARNING" {
                $activityLog.SelectionColor = [System.Drawing.Color]::Yellow
                $activityLog.AppendText("[W] ")
            }
            default {
                $activityLog.SelectionColor = [System.Drawing.Color]::FromArgb(0, 220, 0)
                $activityLog.AppendText("[I] ")
            }
        }
        
        $activityLog.SelectionColor = [System.Drawing.Color]::FromArgb(0, 220, 0)
        $activityLog.AppendText("$Message`r`n")
        $activityLog.ScrollToCaret()
    }

    function Add-Alert {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Type,
            
            [Parameter(Mandatory=$true)]
            [string]$SourceIP,
            
            [Parameter(Mandatory=$true)]
            [string]$Details,
            
            [Parameter(Mandatory=$false)]
            [ValidateSet("HIGH", "MEDIUM", "LOW")]
            [string]$Severity = "MEDIUM"
        )
        
        try {
            $timestamp = Get-Date -Format "HH:mm:ss"
            
            $item = New-Object System.Windows.Forms.ListViewItem($timestamp)
            $item.SubItems.Add($Severity) | Out-Null
            $item.SubItems.Add($Type) | Out-Null
            $item.SubItems.Add($SourceIP) | Out-Null
            $item.SubItems.Add($Details) | Out-Null
            
            switch ($Severity -as [string]) {
                "HIGH" { 
                    $item.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 200)
                    $item.ForeColor = [System.Drawing.Color]::DarkRed
                }
                "MEDIUM" { 
                    $item.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 200)
                    $item.ForeColor = [System.Drawing.Color]::DarkOrange
                }
                "LOW" { 
                    $item.BackColor = [System.Drawing.Color]::FromArgb(200, 255, 200)
                    $item.ForeColor = [System.Drawing.Color]::DarkGreen
                }
            }
            
            $item.UseItemStyleForSubItems = $false
            
            # Set severity subitem color
            $item.SubItems[1].ForeColor = switch ($Severity) {
                "HIGH" { [System.Drawing.Color]::Red }
                "MEDIUM" { [System.Drawing.Color]::Orange }
                "LOW" { [System.Drawing.Color]::Green }
                default { [System.Drawing.Color]::Black }
            }
            
            # Add to list view on UI thread
            if ($alertListView.InvokeRequired) {
                $alertListView.Invoke([System.Action]{
                    $alertListView.Items.Insert(0, $item)
                })
            }
            else {
                $alertListView.Items.Insert(0, $item)
            }
            
            # Trim old items
            if ($alertListView.Items.Count -gt 100) {
                if ($alertListView.InvokeRequired) {
                    $alertListView.Invoke([System.Action]{
                        $alertListView.Items.RemoveAt(99)
                    })
                }
                else {
                    $alertListView.Items.RemoveAt(99)
                }
            }
            
            # Update stats safely
            $script:Stats.Alerts += ,@{
                Time = $timestamp
                Severity = $Severity
                Type = $Type
                SourceIP = $SourceIP
                Details = $Details
            }
        }
        catch {
            Write-IDSLog "Error adding alert: $_" "ERROR"
        }
    }

    function Test-SignatureMatch {
        param([Parameter(Mandatory=$true)]$Connection)
        
        try {
            # Check for suspicious ports
            if ($SignatureRules["Suspicious Ports"].Ports -contains $Connection.RemotePort) {
                return @{
                    Matched = $true
                    Type = "Suspicious Port"
                    SourceIP = $Connection.RemoteAddress.ToString()
                    Details = "Connection to port $($Connection.RemotePort) from $($Connection.RemoteAddress)"
                    Severity = "MEDIUM"
                }
            }
            
            # Check for port scanning behavior
            $sourceIP = $Connection.RemoteAddress.ToString()
            if ($Script:Stats.UniqueIPs.ContainsKey($sourceIP)) {
                $portCount = $Script:Stats.UniqueIPs[$sourceIP].Ports.Count
                if ($portCount -gt $SignatureRules["Port Scan"].Threshold) {
                    return @{
                        Matched = $true
                        Type = "Port Scan"
                        SourceIP = $sourceIP
                        Details = "Possible port scan from $sourceIP - accessed $portCount different ports"
                        Severity = "HIGH"
                    }
                }
            }
            
            # Check for potential data exfiltration (simplified)
            # Note: This is a simplified check. NetTCPConnection doesn't have BytesReceived property.
            # We'll use a placeholder check for established connections
            if ($Connection.State -eq "Established") {
                # This is a placeholder - real implementation would require more sophisticated monitoring
                $random = Get-Random -Minimum 0 -Maximum 100
                if ($random -lt 2) { # 2% chance of triggering data exfiltration alert for demo
                    return @{
                        Matched = $true
                        Type = "Data Exfiltration"
                        SourceIP = $sourceIP
                        Details = "Large data transfer detected (simulated): 15MB"
                        Severity = "HIGH"
                    }
                }
            }
        }
        catch {
            Write-IDSLog "Error in signature matching: $_" "ERROR"
        }
        
        return @{ Matched = $false }
    }

    function Update-Statistics {
        param([Parameter(Mandatory=$true)]$Connection)
        
        try {
            $Script:Stats.TotalConnections++
            
            $remoteAddr = $Connection.RemoteAddress.ToString()
            $remotePort = $Connection.RemotePort
            
            # Track IP statistics
            if (![string]::IsNullOrEmpty($remoteAddr) -and $remoteAddr -ne "0.0.0.0" -and $remoteAddr -ne "::") {
                if (!$Script:Stats.UniqueIPs.ContainsKey($remoteAddr)) {
                    $Script:Stats.UniqueIPs[$remoteAddr] = @{
                        Ports = @()
                        Count = 0
                        FirstSeen = Get-Date
                    }
                }
                
                $Script:Stats.UniqueIPs[$remoteAddr].Count++
                
                if ($Script:Stats.UniqueIPs[$remoteAddr].Ports -notcontains $remotePort) {
                    $Script:Stats.UniqueIPs[$remoteAddr].Ports += $remotePort
                }
            }
            
            # Track port activity
            if (!$Script:Stats.PortActivity.ContainsKey($remotePort)) {
                $Script:Stats.PortActivity[$remotePort] = 0
            }
            $Script:Stats.PortActivity[$remotePort]++
        }
        catch {
            Write-IDSLog "Error updating statistics: $_" "ERROR"
        }
    }

    function Update-GUI {
        try {
            # Update stats cards
            foreach ($control in $statsPanel.Controls) {
                if ($control.GetType().Name -eq "Panel") {
                    $valueLabel = $null
                    
                    foreach ($child in $control.Controls) {
                        if ($child.Location.Y -eq 35 -and $child.GetType().Name -eq "Label") {
                            $valueLabel = $child
                            break
                        }
                    }
                    
                    if ($valueLabel) {
                        switch ($control.Tag) {
                            "Connections" { $valueLabel.Text = $Script:Stats.TotalConnections.ToString() }
                            "Unique IPs" { $valueLabel.Text = $Script:Stats.UniqueIPs.Count.ToString() }
                            "Alerts" { 
                                $alertCount = $Script:Stats.Alerts.Count
                                $valueLabel.Text = $alertCount.ToString()
                                $valueLabel.ForeColor = if ($alertCount -gt 0) { 
                                    [System.Drawing.Color]::Red 
                                } else { 
                                    [System.Drawing.Color]::FromArgb(40, 40, 140) 
                                }
                            }
                            "Runtime" { 
                                $runtime = [math]::Round(((Get-Date) - $Script:Stats.StartTime).TotalSeconds, 0)
                                $valueLabel.Text = "${runtime}s"
                            }
                            "Conn/Min" {
                                $runtime = [math]::Round(((Get-Date) - $Script:Stats.StartTime).TotalSeconds, 0)
                                $rate = if ($runtime -gt 0) { 
                                    [math]::Round(($Script:Stats.TotalConnections / $runtime) * 60, 1) 
                                } else { 
                                    0 
                                }
                                $valueLabel.Text = $rate.ToString()
                            }
                            "Top Port" {
                                if ($Script:Stats.PortActivity.Count -gt 0) {
                                    $topPort = $Script:Stats.PortActivity.GetEnumerator() | 
                                        Sort-Object Value -Descending | 
                                        Select-Object -First 1
                                    $valueLabel.Text = "$($topPort.Key) ($($topPort.Value))"
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-IDSLog "Error updating GUI: $_" "ERROR"
        }
    }

    # Timer tick event with comprehensive error handling
    $timer.Add_Tick({
        try {
            if (!$Script:Stats.IsMonitoring) { 
                return 
            }
            
            # Get active network connections with proper error handling
            try {
                $connections = Get-NetTCPConnection -State Established -ErrorAction Stop | 
                    Where-Object { 
                        $_.RemoteAddress -ne "0.0.0.0" -and 
                        $_.RemoteAddress -ne "::" -and 
                        $_.RemotePort -ne 0 
                    }
            }
            catch {
                Write-IDSLog "Error retrieving network connections: $_" "WARNING"
                return
            }
            
            if (!$connections) { 
                return 
            }
            
            foreach ($conn in $connections) {
                Update-Statistics $conn
                
                $signatureMatch = Test-SignatureMatch $conn
                if ($signatureMatch.Matched) {
                    Add-Alert -Type $signatureMatch.Type -SourceIP $signatureMatch.SourceIP `
                        -Details $signatureMatch.Details -Severity $signatureMatch.Severity
                    Write-IDSLog "ALERT: $($signatureMatch.Type) - $($signatureMatch.Details)" "ALERT"
                }
            }
            
            # Update GUI on UI thread
            if ($form.InvokeRequired) {
                $form.Invoke([System.Action]{ Update-GUI })
            }
            else {
                Update-GUI
            }
        }
        catch {
            Write-IDSLog "Critical error during monitoring cycle: $_" "ERROR"
        }
    })

    # Button event handlers
    $script:buttons["start"].Add_Click({
        try {
            if ($Script:Stats.IsMonitoring) { 
                return 
            }
            
            # Reset statistics
            $Script:Stats = @{
                TotalConnections = 0
                UniqueIPs = @{}
                PortActivity = @{}
                Alerts = @()
                StartTime = Get-Date
                IsMonitoring = $true
                ConnectionHistory = New-Object System.Collections.Queue
            }
            
            $timer.Start()
            $script:buttons["start"].Enabled = $false
            $script:buttons["stop"].Enabled = $true
            
            $statusLabel.Text = " STATUS: MONITORING"
            $statusLabel.ForeColor = [System.Drawing.Color]::LimeGreen
            $statusIndicator.BackColor = [System.Drawing.Color]::LimeGreen
            $statusIndicator.Tag = "monitoring"
            
            Write-IDSLog "IDS monitoring started" "INFO"
            Update-ActivityLog "=== Monitoring Started at $(Get-Date -Format 'HH:mm:ss') ===" "INFO"
        }
        catch {
            Write-IDSLog "Error starting monitoring: $_" "ERROR"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to start monitoring: $_",
                "Start Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    })

    $script:buttons["stop"].Add_Click({
        try {
            if (!$Script:Stats.IsMonitoring) { 
                return 
            }
            
            $timer.Stop()
            $script:buttons["start"].Enabled = $true
            $script:buttons["stop"].Enabled = $false
            
            $statusLabel.Text = " STATUS: STOPPED"
            $statusLabel.ForeColor = [System.Drawing.Color]::White
            $statusIndicator.BackColor = [System.Drawing.Color]::Red
            $statusIndicator.Tag = "stopped"
            
            $Script:Stats.IsMonitoring = $false
            
            Write-IDSLog "IDS monitoring stopped" "INFO"
            Update-ActivityLog "=== Monitoring Stopped at $(Get-Date -Format 'HH:mm:ss') ===" "INFO"
        }
        catch {
            Write-IDSLog "Error stopping monitoring: $_" "ERROR"
        }
    })

    $script:buttons["clear"].Add_Click({
        try {
            # Clear on UI thread
            if ($alertListView.InvokeRequired) {
                $alertListView.Invoke([System.Action]{
                    $alertListView.Items.Clear()
                })
            }
            else {
                $alertListView.Items.Clear()
            }
            
            Write-IDSLog "Alerts cleared" "INFO"
        }
        catch {
            Write-IDSLog "Error clearing alerts: $_" "ERROR"
        }
    })

    $script:buttons["export"].Add_Click({
        try {
            $exportPath = "$LogPath\IDS_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            
            # Build report with error handling
            $reportLines = @()
            $reportLines += "=== ENHANCED IDS MONITORING REPORT ==="
            $reportLines += "Generated: $(Get-Date)"
            $reportLines += "Monitoring Period: $($Script:Stats.StartTime) to $(Get-Date)"
            $reportLines += "Total Connections: $($Script:Stats.TotalConnections)"
            $reportLines += "Unique IPs: $($Script:Stats.UniqueIPs.Count)"
            $reportLines += "Total Alerts: $($Script:Stats.Alerts.Count)"
            $reportLines += ""
            $reportLines += "=== NETWORK STATISTICS ==="
            $reportLines += "Top 5 Active Ports:"
            
            if ($Script:Stats.PortActivity.Count -gt 0) {
                $topPorts = $Script:Stats.PortActivity.GetEnumerator() | 
                    Sort-Object Value -Descending | 
                    Select-Object -First 5
                
                foreach ($port in $topPorts) {
                    $reportLines += "$($port.Key): $($port.Value) connections"
                }
            } else {
                $reportLines += "No port activity recorded"
            }
            
            $reportLines += ""
            $reportLines += "=== RECENT ALERTS ==="
            
            $alertItems = @()
            # Capture alert items safely
            if ($alertListView.InvokeRequired) {
                $alertItems = $alertListView.Invoke([Func[System.Object[]]]{
                    @($alertListView.Items | Select-Object -First 20)
                })
            }
            else {
                $alertItems = @($alertListView.Items | Select-Object -First 20)
            }
            
            if ($alertItems.Count -gt 0) {
                foreach ($item in $alertItems) {
                    $reportLines += "$($item.Text) | $($item.SubItems[1].Text) | $($item.SubItems[2].Text) | $($item.SubItems[4].Text)"
                }
            } else {
                $reportLines += "No alerts detected during this session"
            }
            
            $reportLines += ""
            $reportLines += "=== LOG FILES ==="
            $reportLines += "- Main Log: $LogFile"
            $reportLines += "- Alert Log: $AlertFile"
            
            $report = $reportLines -join "`r`n"
            
            # Export report
            $report | Out-File -FilePath $exportPath -Force -ErrorAction Stop
            
            $msg = "Report exported successfully to:`n$exportPath`n`nDo you want to open the file now?"
            $result = [System.Windows.Forms.MessageBox]::Show(
                $msg, 
                "Export Complete", 
                [System.Windows.Forms.MessageBoxButtons]::YesNo, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                try {
                    Start-Process $exportPath
                }
                catch {
                    Write-IDSLog "Error opening exported file: $_" "ERROR"
                }
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export logs: $_", 
                "Export Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            Write-IDSLog "Export failed: $_" "ERROR"
        }
    })

    $script:buttons["settings"].Add_Click({
        try {
            $settingsForm = New-Object System.Windows.Forms.Form
            $settingsForm.Text = "IDS Settings"
            $settingsForm.Size = New-Object System.Drawing.Size(500, 350)
            $settingsForm.StartPosition = "CenterScreen"
            $settingsForm.BackColor = [System.Drawing.Color]::White
            $settingsForm.TopMost = $true
            
            $label = New-Object System.Windows.Forms.Label
            $label.Text = "Detection Threshold Settings"
            $label.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
            $label.Location = New-Object System.Drawing.Point(20, 20)
            $label.AutoSize = $true
            $settingsForm.Controls.Add($label)
            
            $portScanLabel = New-Object System.Windows.Forms.Label
            $portScanLabel.Text = "Port Scan Threshold:"
            $portScanLabel.Location = New-Object System.Drawing.Point(40, 70)
            $portScanLabel.AutoSize = $true
            $settingsForm.Controls.Add($portScanLabel)
            
            $portScanInput = New-Object System.Windows.Forms.NumericUpDown
            $portScanInput.Location = New-Object System.Drawing.Point(220, 68)
            $portScanInput.Size = New-Object System.Drawing.Size(60, 22)
            $portScanInput.Minimum = 5
            $portScanInput.Maximum = 100
            $portScanInput.Value = $SignatureRules["Port Scan"].Threshold
            $settingsForm.Controls.Add($portScanInput)
            
            $bruteForceLabel = New-Object System.Windows.Forms.Label
            $bruteForceLabel.Text = "Brute Force Threshold:"
            $bruteForceLabel.Location = New-Object System.Drawing.Point(40, 110)
            $bruteForceLabel.AutoSize = $true
            $settingsForm.Controls.Add($bruteForceLabel)
            
            $bruteForceInput = New-Object System.Windows.Forms.NumericUpDown
            $bruteForceInput.Location = New-Object System.Drawing.Point(220, 108)
            $bruteForceInput.Size = New-Object System.Drawing.Size(60, 22)
            $bruteForceInput.Minimum = 3
            $bruteForceInput.Maximum = 50
            $bruteForceInput.Value = $SignatureRules["Brute Force"].Threshold
            $settingsForm.Controls.Add($bruteForceInput)
            
            $saveButton = New-Object System.Windows.Forms.Button
            $saveButton.Text = "Save Settings"
            $saveButton.Location = New-Object System.Drawing.Point(100, 250)
            $saveButton.Size = New-Object System.Drawing.Size(120, 35)
            $saveButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
            $saveButton.ForeColor = [System.Drawing.Color]::White
            $saveButton.FlatStyle = "Flat"
            $settingsForm.Controls.Add($saveButton)
            
            $cancelButton = New-Object System.Windows.Forms.Button
            $cancelButton.Text = "Cancel"
            $cancelButton.Location = New-Object System.Drawing.Point(260, 250)
            $cancelButton.Size = New-Object System.Drawing.Size(120, 35)
            $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
            $cancelButton.FlatStyle = "Flat"
            $settingsForm.Controls.Add($cancelButton)
            
            $saveButton.Add_Click({
                $SignatureRules["Port Scan"].Threshold = $portScanInput.Value
                $SignatureRules["Brute Force"].Threshold = $bruteForceInput.Value
                Write-IDSLog "Detection thresholds updated: Port Scan=$($portScanInput.Value), Brute Force=$($bruteForceInput.Value)" "INFO"
                $settingsForm.Close()
            })
            
            $cancelButton.Add_Click({ $settingsForm.Close() })
            
            [void]$settingsForm.ShowDialog()
        }
        catch {
            Write-IDSLog "Error in settings dialog: $_" "ERROR"
            [System.Windows.Forms.MessageBox]::Show(
                "Settings dialog error: $_",
                "Dialog Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    })

    # Initialize with welcome message
    Write-IDSLog "Enhanced Network Intrusion Detection System initialized" "INFO"
    Update-ActivityLog "=== Enhanced Network IDS Ready ===" "INFO"
    Update-ActivityLog "System started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Update-ActivityLog "Click the 'Start Monitoring' button to begin network surveillance" "INFO"
    Update-ActivityLog "Warning: This application requires administrator privileges to monitor network traffic" "WARNING"

    # Show form
    [void]$form.ShowDialog()
}
catch {
    # Top-level exception handler
    $errorMsg = "A critical error occurred:`n`n$_`n`nStack Trace:`n$($_.ScriptStackTrace)"
    
    try {
        # Try to show error in message box
        [System.Windows.Forms.MessageBox]::Show(
            $errorMsg,
            "Application Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    catch {
        # Fallback to console if UI is unavailable
        Write-Error $errorMsg
    }
    
    # Log error to file as final fallback
    try {
        $fallbackLog = "$env:TEMP\IDS_Crash_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [CRITICAL] $errorMsg" | Out-File -FilePath $fallbackLog -Append
    }
    catch {
        # Nothing we can do at this point
    }
    
    exit 1
}
finally {
    # Cleanup resources
    try {
        if ($script:timer) {
            $script:timer.Stop()
            $script:timer.Dispose()
        }
        
        if ($form) {
            $form.Dispose()
        }
    }
    catch {
        # Swallow cleanup errors to avoid masking original exception
    }
}
