# Network Intrusion Detection System (IDS) with GUI
# Monitors network traffic for suspicious patterns and potential threats

#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create log directory
$LogPath = "$env:TEMP\IDS_Logs"
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$LogFile = Join-Path $LogPath "IDS_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$AlertFile = Join-Path $LogPath "IDS_Alerts_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
}

# Anomaly detection baselines
$AnomalyBaseline = @{
    MaxConnectionsPerMinute = 100
    UnusualHours = @(0..5)
}

# Statistics tracking
$Script:Stats = @{
    TotalConnections = 0
    UniqueIPs = @{}
    PortActivity = @{}
    Alerts = @()
    StartTime = Get-Date
    IsMonitoring = $false
}

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Network Intrusion Detection System"
$form.Size = New-Object System.Drawing.Size(1000, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)

# Header Panel
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.Size = New-Object System.Drawing.Size(1000, 60)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "🛡️ Network Intrusion Detection System"
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$titleLabel.Size = New-Object System.Drawing.Size(500, 30)
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::White
$headerPanel.Controls.Add($titleLabel)

# Status Label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Status: Stopped"
$statusLabel.Location = New-Object System.Drawing.Point(750, 20)
$statusLabel.Size = New-Object System.Drawing.Size(200, 20)
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$statusLabel.ForeColor = [System.Drawing.Color]::White
$headerPanel.Controls.Add($statusLabel)

# Statistics Panel
$statsPanel = New-Object System.Windows.Forms.Panel
$statsPanel.Location = New-Object System.Drawing.Point(20, 80)
$statsPanel.Size = New-Object System.Drawing.Size(950, 100)
$statsPanel.BackColor = [System.Drawing.Color]::White
$statsPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($statsPanel)

# Statistics Labels
$connLabel = New-Object System.Windows.Forms.Label
$connLabel.Text = "Total Connections: 0"
$connLabel.Location = New-Object System.Drawing.Point(20, 15)
$connLabel.Size = New-Object System.Drawing.Size(200, 25)
$connLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statsPanel.Controls.Add($connLabel)

$ipLabel = New-Object System.Windows.Forms.Label
$ipLabel.Text = "Unique IPs: 0"
$ipLabel.Location = New-Object System.Drawing.Point(250, 15)
$ipLabel.Size = New-Object System.Drawing.Size(200, 25)
$ipLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statsPanel.Controls.Add($ipLabel)

$alertLabel = New-Object System.Windows.Forms.Label
$alertLabel.Text = "Total Alerts: 0"
$alertLabel.Location = New-Object System.Drawing.Point(480, 15)
$alertLabel.Size = New-Object System.Drawing.Size(200, 25)
$alertLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$alertLabel.ForeColor = [System.Drawing.Color]::Red
$statsPanel.Controls.Add($alertLabel)

$timeLabel = New-Object System.Windows.Forms.Label
$timeLabel.Text = "Runtime: 0s"
$timeLabel.Location = New-Object System.Drawing.Point(710, 15)
$timeLabel.Size = New-Object System.Drawing.Size(200, 25)
$timeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statsPanel.Controls.Add($timeLabel)

$rateLabel = New-Object System.Windows.Forms.Label
$rateLabel.Text = "Connection Rate: 0/min"
$rateLabel.Location = New-Object System.Drawing.Point(20, 50)
$rateLabel.Size = New-Object System.Drawing.Size(250, 25)
$rateLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statsPanel.Controls.Add($rateLabel)

$topPortLabel = New-Object System.Windows.Forms.Label
$topPortLabel.Text = "Top Port: N/A"
$topPortLabel.Location = New-Object System.Drawing.Point(300, 50)
$topPortLabel.Size = New-Object System.Drawing.Size(300, 25)
$topPortLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$statsPanel.Controls.Add($topPortLabel)

# Alert ListView
$alertListView = New-Object System.Windows.Forms.ListView
$alertListView.Location = New-Object System.Drawing.Point(20, 200)
$alertListView.Size = New-Object System.Drawing.Size(950, 250)
$alertListView.View = [System.Windows.Forms.View]::Details
$alertListView.FullRowSelect = $true
$alertListView.GridLines = $true
$alertListView.Font = New-Object System.Drawing.Font("Consolas", 9)
$alertListView.Columns.Add("Time", 150) | Out-Null
$alertListView.Columns.Add("Severity", 80) | Out-Null
$alertListView.Columns.Add("Type", 120) | Out-Null
$alertListView.Columns.Add("Details", 570) | Out-Null
$form.Controls.Add($alertListView)

# Activity Log
$activityLog = New-Object System.Windows.Forms.TextBox
$activityLog.Location = New-Object System.Drawing.Point(20, 470)
$activityLog.Size = New-Object System.Drawing.Size(950, 120)
$activityLog.Multiline = $true
$activityLog.ScrollBars = "Vertical"
$activityLog.ReadOnly = $true
$activityLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$activityLog.BackColor = [System.Drawing.Color]::Black
$activityLog.ForeColor = [System.Drawing.Color]::LimeGreen
$form.Controls.Add($activityLog)

# Control Buttons
$startButton = New-Object System.Windows.Forms.Button
$startButton.Location = New-Object System.Drawing.Point(20, 610)
$startButton.Size = New-Object System.Drawing.Size(120, 35)
$startButton.Text = "Start Monitoring"
$startButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$startButton.BackColor = [System.Drawing.Color]::FromArgb(0, 180, 0)
$startButton.ForeColor = [System.Drawing.Color]::White
$startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$form.Controls.Add($startButton)

$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Location = New-Object System.Drawing.Point(150, 610)
$stopButton.Size = New-Object System.Drawing.Size(120, 35)
$stopButton.Text = "Stop Monitoring"
$stopButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$stopButton.BackColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
$stopButton.ForeColor = [System.Drawing.Color]::White
$stopButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$stopButton.Enabled = $false
$form.Controls.Add($stopButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Location = New-Object System.Drawing.Point(280, 610)
$clearButton.Size = New-Object System.Drawing.Size(120, 35)
$clearButton.Text = "Clear Alerts"
$clearButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$clearButton.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$clearButton.ForeColor = [System.Drawing.Color]::White
$clearButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$form.Controls.Add($clearButton)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Location = New-Object System.Drawing.Point(410, 610)
$exportButton.Size = New-Object System.Drawing.Size(120, 35)
$exportButton.Text = "Export Logs"
$exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$exportButton.ForeColor = [System.Drawing.Color]::White
$exportButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$form.Controls.Add($exportButton)

# Timer for monitoring
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000  # 2 seconds

# Functions
function Write-IDSLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
    
    if ($Level -eq "ALERT") {
        Add-Content -Path $AlertFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    
    # Update activity log
    $activityLog.AppendText("$logMessage`r`n")
    $activityLog.SelectionStart = $activityLog.Text.Length
    $activityLog.ScrollToCaret()
}

function Add-Alert {
    param([string]$Type, [string]$Details, [string]$Severity = "MEDIUM")
    
    $item = New-Object System.Windows.Forms.ListViewItem((Get-Date -Format "HH:mm:ss"))
    $item.SubItems.Add($Severity) | Out-Null
    $item.SubItems.Add($Type) | Out-Null
    $item.SubItems.Add($Details) | Out-Null
    
    switch ($Severity) {
        "HIGH" { $item.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 200) }
        "MEDIUM" { $item.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 200) }
        "LOW" { $item.BackColor = [System.Drawing.Color]::FromArgb(200, 255, 200) }
    }
    
    $alertListView.Items.Insert(0, $item)
    
    if ($alertListView.Items.Count -gt 100) {
        $alertListView.Items.RemoveAt(100)
    }
}

function Test-SignatureMatch {
    param($Connection)
    
    if ($SignatureRules["Suspicious Ports"].Ports -contains $Connection.RemotePort) {
        return @{
            Matched = $true
            Type = "Suspicious Port"
            Details = "Connection to port $($Connection.RemotePort) from $($Connection.RemoteAddress)"
            Severity = "MEDIUM"
        }
    }
    
    $sourceIP = $Connection.RemoteAddress
    if ($Script:Stats.UniqueIPs.ContainsKey($sourceIP)) {
        $portCount = $Script:Stats.UniqueIPs[$sourceIP].Ports.Count
        if ($portCount -gt $SignatureRules["Port Scan"].Threshold) {
            return @{
                Matched = $true
                Type = "Port Scan"
                Details = "Possible port scan from $sourceIP ($portCount ports)"
                Severity = "HIGH"
            }
        }
    }
    
    return @{ Matched = $false }
}

function Update-Statistics {
    param($Connection)
    
    $Script:Stats.TotalConnections++
    
    $remoteAddr = $Connection.RemoteAddress
    $remotePort = $Connection.RemotePort
    
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
    
    if (!$Script:Stats.PortActivity.ContainsKey($remotePort)) {
        $Script:Stats.PortActivity[$remotePort] = 0
    }
    $Script:Stats.PortActivity[$remotePort]++
}

function Update-GUI {
    $connLabel.Text = "Total Connections: $($Script:Stats.TotalConnections)"
    $ipLabel.Text = "Unique IPs: $($Script:Stats.UniqueIPs.Count)"
    $alertLabel.Text = "Total Alerts: $($Script:Stats.Alerts.Count)"
    
    $runtime = [math]::Round(((Get-Date) - $Script:Stats.StartTime).TotalSeconds, 0)
    $timeLabel.Text = "Runtime: ${runtime}s"
    
    $rate = if ($runtime -gt 0) { [math]::Round(($Script:Stats.TotalConnections / $runtime) * 60, 1) } else { 0 }
    $rateLabel.Text = "Connection Rate: $rate/min"
    
    if ($Script:Stats.PortActivity.Count -gt 0) {
        $topPort = $Script:Stats.PortActivity.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
        $topPortLabel.Text = "Top Port: $($topPort.Key) ($($topPort.Value) connections)"
    }
}

# Timer tick event
$timer.Add_Tick({
    try {
        $connections = Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue
        
        foreach ($conn in $connections) {
            Update-Statistics $conn
            
            $signatureMatch = Test-SignatureMatch $conn
            if ($signatureMatch.Matched) {
                Add-Alert -Type $signatureMatch.Type -Details $signatureMatch.Details -Severity $signatureMatch.Severity
                Write-IDSLog "ALERT: $($signatureMatch.Type) - $($signatureMatch.Details)" "ALERT"
                $Script:Stats.Alerts += $signatureMatch
            }
        }
        
        Update-GUI
        
    } catch {
        Write-IDSLog "Error during monitoring: $_" "ERROR"
    }
})

# Button events
$startButton.Add_Click({
    $Script:Stats = @{
        TotalConnections = 0
        UniqueIPs = @{}
        PortActivity = @{}
        Alerts = @()
        StartTime = Get-Date
        IsMonitoring = $true
    }
    
    $timer.Start()
    $startButton.Enabled = $false
    $stopButton.Enabled = $true
    $statusLabel.Text = "Status: Monitoring"
    $statusLabel.ForeColor = [System.Drawing.Color]::LimeGreen
    
    Write-IDSLog "IDS monitoring started"
    $activityLog.AppendText("=== Monitoring Started ===`r`n")
})

$stopButton.Add_Click({
    $timer.Stop()
    $startButton.Enabled = $true
    $stopButton.Enabled = $false
    $statusLabel.Text = "Status: Stopped"
    $statusLabel.ForeColor = [System.Drawing.Color]::White
    $Script:Stats.IsMonitoring = $false
    
    Write-IDSLog "IDS monitoring stopped"
    $activityLog.AppendText("=== Monitoring Stopped ===`r`n")
})

$clearButton.Add_Click({
    $alertListView.Items.Clear()
    $activityLog.Clear()
    Write-IDSLog "Alerts cleared"
})

$exportButton.Add_Click({
    $exportPath = "$LogPath\IDS_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    $report = @"
=== IDS Monitoring Report ===
Generated: $(Get-Date)
Total Connections: $($Script:Stats.TotalConnections)
Unique IPs: $($Script:Stats.UniqueIPs.Count)
Total Alerts: $($Script:Stats.Alerts.Count)

=== Recent Alerts ===
$($alertListView.Items | ForEach-Object { "$($_.Text) - $($_.SubItems[1].Text) - $($_.SubItems[2].Text) - $($_.SubItems[3].Text)" } | Out-String)

Log files:
- Main Log: $LogFile
- Alert Log: $AlertFile
"@
    
    $report | Out-File -FilePath $exportPath
    [System.Windows.Forms.MessageBox]::Show("Report exported to:`n$exportPath", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

# Show form
Write-IDSLog "IDS GUI initialized"
$activityLog.AppendText("=== Network IDS Ready ===`r`n")
$activityLog.AppendText("Click 'Start Monitoring' to begin...`r`n")

[void]$form.ShowDialog()
