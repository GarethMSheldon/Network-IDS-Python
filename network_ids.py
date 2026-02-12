#!/usr/bin/env python3
"""
Network Intrusion Detection System - Python Version
Monitors network connections and Windows Event Logs for suspicious activity
Requires: Python 3.8+, Administrator privileges on Windows
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import datetime
import json
import os
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
import sys

# Platform-specific imports
if sys.platform == 'win32':
    import ctypes
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import psutil
else:
    import psutil


class NetworkIDS:
    """Main IDS Application Class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Intrusion Detection System - Enhanced")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'unique_ips': {},
            'port_activity': defaultdict(int),
            'alerts': [],
            'start_time': None,
            'is_monitoring': False,
            'network_alerts': 0,
            'event_alerts': 0,
            'last_event_check': datetime.datetime.now(),
            'processed_events': {}
        }
        
        # Detection rules
        self.signature_rules = {
            'port_scan': {
                'threshold': 10,
                'description': 'Multiple ports from same source'
            },
            'brute_force': {
                'threshold': 5,
                'description': 'Multiple failed auth attempts'
            },
            'suspicious_ports': {
                'ports': [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 8080],
                'description': 'Connection to known suspicious ports'
            },
            'failed_logon': {
                'threshold': 5,
                'event_id': 4625,
                'time_window': 300
            },
            'account_lockout': {
                'threshold': 1,
                'event_id': 4740,
                'time_window': 300
            }
        }
        
        # Event log signatures (Windows only)
        self.event_signatures = {
            4625: 'Failed logon attempt',
            4740: 'Account locked out',
            4720: 'User account created',
            4726: 'User account deleted',
            4732: 'Member added to security group',
            4719: 'System audit policy changed',
            1102: 'Security audit log cleared',
            4688: 'New process created',
            4672: 'Special privileges assigned'
        }
        
        # Monitoring thread
        self.monitor_thread = None
        self.stop_monitoring = threading.Event()
        
        # Log directory
        self.log_path = Path(os.environ.get('TEMP', '/tmp')) / 'Enhanced_IDS_Logs'
        self.log_path.mkdir(exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = self.log_path / f'IDS_{timestamp}.log'
        self.alert_file = self.log_path / f'IDS_Alerts_{timestamp}.log'
        
        # Build GUI
        self.build_gui()
        
        # Log startup
        self.write_log("Enhanced Network IDS initialized", "INFO")
        self.update_activity_log("=== Enhanced Network IDS Ready ===", "INFO")
        self.update_activity_log(f"System started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "INFO")
        self.update_activity_log("Monitoring: Network Traffic + Windows Security Events", "INFO")
        self.update_activity_log("Click 'Start Monitoring' to begin surveillance", "INFO")
        
        if sys.platform != 'win32':
            self.update_activity_log("WARNING: Event log monitoring only available on Windows", "WARNING")
    
    def build_gui(self):
        """Build the GUI interface"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#1e3c7d', height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="NETWORK INTRUSION DETECTION SYSTEM - ENHANCED",
            font=('Segoe UI', 16, 'bold'),
            bg='#1e3c7d',
            fg='white'
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Network Traffic + Windows Event Log Monitoring",
            font=('Segoe UI', 9),
            bg='#1e3c7d',
            fg='#c8c8ff'
        )
        subtitle_label.place(x=20, y=45)
        
        # Status indicator
        self.status_frame = tk.Frame(header_frame, bg='#1e3c7d')
        self.status_frame.place(x=900, y=25)
        
        self.status_indicator = tk.Canvas(self.status_frame, width=15, height=15, bg='#1e3c7d', highlightthickness=0)
        self.status_indicator.create_oval(2, 2, 13, 13, fill='red', outline='white')
        self.status_indicator.pack(side=tk.LEFT)
        
        self.status_label = tk.Label(
            self.status_frame,
            text=" STATUS: STOPPED",
            font=('Segoe UI', 10, 'bold'),
            bg='#1e3c7d',
            fg='white'
        )
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Statistics cards
        stats_frame = tk.Frame(self.root, bg='white', height=140)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        stats_frame.pack_propagate(False)
        
        self.stat_cards = {}
        card_info = [
            ('Connections', 'C', '#2858a8'),
            ('Unique IPs', 'IP', '#2858a8'),
            ('Net Alerts', 'N', '#dc143c'),
            ('Event Alerts', 'E', '#ff4500'),
            ('Runtime', 'T', '#2858a8'),
            ('Top Port', 'P', '#2858a8')
        ]
        
        for i, (name, icon, color) in enumerate(card_info):
            card_data = self.create_stat_card(stats_frame, name, icon, color)
            card_data['frame'].place(x=i*195 + 10, y=10)
            self.stat_cards[name] = card_data
        
        # Alerts section
        alert_frame = tk.Frame(self.root, bg='white')
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        alert_label = tk.Label(
            alert_frame,
            text="SECURITY ALERTS (Network + Event Logs)",
            font=('Segoe UI', 12, 'bold'),
            bg='white',
            fg='#1e1e1e'
        )
        alert_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # Alert treeview
        columns = ('Time', 'Source', 'Severity', 'Type', 'IP/User', 'Details')
        self.alert_tree = ttk.Treeview(alert_frame, columns=columns, show='headings', height=12)
        
        # Configure columns
        self.alert_tree.heading('Time', text='Time')
        self.alert_tree.heading('Source', text='Source')
        self.alert_tree.heading('Severity', text='Severity')
        self.alert_tree.heading('Type', text='Type')
        self.alert_tree.heading('IP/User', text='IP/User')
        self.alert_tree.heading('Details', text='Details')
        
        self.alert_tree.column('Time', width=100)
        self.alert_tree.column('Source', width=80)
        self.alert_tree.column('Severity', width=80)
        self.alert_tree.column('Type', width=140)
        self.alert_tree.column('IP/User', width=130)
        self.alert_tree.column('Details', width=500)
        
        # Scrollbar for alerts
        alert_scroll = ttk.Scrollbar(alert_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=alert_scroll.set)
        
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        alert_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for colors
        self.alert_tree.tag_configure('HIGH', background='#ffcccc', foreground='#8b0000')
        self.alert_tree.tag_configure('MEDIUM', background='#ffffcc', foreground='#ff8c00')
        self.alert_tree.tag_configure('LOW', background='#ccffcc', foreground='#006400')
        
        # Activity log
        log_frame = tk.Frame(self.root, bg='white')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        log_label = tk.Label(
            log_frame,
            text="SYSTEM ACTIVITY LOG",
            font=('Segoe UI', 12, 'bold'),
            bg='white',
            fg='#1e1e1e'
        )
        log_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            bg='#141414',
            fg='#00dc00',
            font=('Consolas', 9),
            insertbackground='#00dc00'
        )
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.activity_log.configure(state='disabled')
        
        # Buttons
        btn_frame = tk.Frame(self.root, bg='#f5f5f5', height=60)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        btn_frame.pack_propagate(False)
        
        button_configs = [
            ('Start Monitoring', self.start_monitoring, '#009600'),
            ('Stop Monitoring', self.stop_monitoring_action, '#b40000'),
            ('Clear Alerts', self.clear_alerts, '#646464'),
            ('Export Logs', self.export_logs, '#0064c8'),
            ('Settings', self.show_settings, '#5050b4')
        ]
        
        self.buttons = {}
        for i, (text, command, color) in enumerate(button_configs):
            btn = tk.Button(
                btn_frame,
                text=text,
                command=command,
                bg=color,
                fg='white',
                font=('Segoe UI', 9, 'bold'),
                width=15,
                height=2,
                relief=tk.FLAT,
                cursor='hand2'
            )
            btn.place(x=i*155 + 20, y=10)
            self.buttons[text] = btn
            
            # Hover effects
            btn.bind('<Enter>', lambda e, b=btn, c=color: b.configure(bg=self.lighten_color(c)))
            btn.bind('<Leave>', lambda e, b=btn, c=color: b.configure(bg=c))
        
        # Initially disable stop button
        self.buttons['Stop Monitoring'].configure(state='disabled')
    
    def create_stat_card(self, parent, title, icon, color):
        """Create a statistics card"""
        card_frame = tk.Frame(parent, bg='white', relief=tk.SOLID, borderwidth=1)
        card_frame.configure(width=170, height=80)
        card_frame.pack_propagate(False)
        
        title_label = tk.Label(
            card_frame,
            text=title,
            font=('Segoe UI', 9, 'bold'),
            bg='white',
            fg='#505050'
        )
        title_label.place(x=15, y=10)
        
        value_label = tk.Label(
            card_frame,
            text='0',
            font=('Segoe UI', 14, 'bold'),
            bg='white',
            fg=color
        )
        value_label.place(x=15, y=35)
        
        icon_label = tk.Label(
            card_frame,
            text=icon,
            font=('Segoe UI', 14, 'bold'),
            bg='white',
            fg='#6464c8'
        )
        icon_label.place(x=115, y=20)
        
        return {'frame': card_frame, 'value': value_label, 'title': title}
    
    def lighten_color(self, hex_color):
        """Lighten a hex color"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + 30)
        g = min(255, g + 30)
        b = min(255, b + 30)
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def write_log(self, message: str, level: str = "INFO"):
        """Write to log file"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            
            if level == "ALERT":
                with open(self.alert_file, 'a', encoding='utf-8') as f:
                    f.write(log_entry)
        except Exception as e:
            print(f"Error writing log: {e}")
    
    def update_activity_log(self, message: str, level: str = "INFO"):
        """Update activity log display"""
        def update():
            self.activity_log.configure(state='normal')
            
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            
            if level == "ALERT":
                prefix = "[!] "
            elif level == "ERROR":
                prefix = "[E] "
            elif level == "WARNING":
                prefix = "[W] "
            else:
                prefix = "[I] "
            
            self.activity_log.insert(tk.END, f"{prefix}{message}\n")
            self.activity_log.see(tk.END)
            self.activity_log.configure(state='disabled')
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update)
        else:
            update()
    
    def add_alert(self, alert_type: str, target: str, details: str, 
                  severity: str = "MEDIUM", source: str = "Network"):
        """Add an alert to the display"""
        def add():
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            
            values = (timestamp, source, severity, alert_type, target, details)
            self.alert_tree.insert('', 0, values=values, tags=(severity,))
            
            # Limit to 100 items
            items = self.alert_tree.get_children()
            if len(items) > 100:
                self.alert_tree.delete(items[-1])
            
            # Update stats
            self.stats['alerts'].append({
                'time': timestamp,
                'source': source,
                'severity': severity,
                'type': alert_type,
                'target': target,
                'details': details
            })
            
            if source == "Network":
                self.stats['network_alerts'] += 1
            else:
                self.stats['event_alerts'] += 1
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, add)
        else:
            add()
    
    def update_stats_display(self):
        """Update statistics display"""
        def update():
            # Connections
            self.stat_cards['Connections']['value'].configure(
                text=str(self.stats['total_connections'])
            )
            
            # Unique IPs
            self.stat_cards['Unique IPs']['value'].configure(
                text=str(len(self.stats['unique_ips']))
            )
            
            # Network Alerts
            net_alerts = self.stats['network_alerts']
            self.stat_cards['Net Alerts']['value'].configure(
                text=str(net_alerts),
                fg='#dc143c' if net_alerts > 0 else '#2858a8'
            )
            
            # Event Alerts
            evt_alerts = self.stats['event_alerts']
            self.stat_cards['Event Alerts']['value'].configure(
                text=str(evt_alerts),
                fg='#ff4500' if evt_alerts > 0 else '#2858a8'
            )
            
            # Runtime
            if self.stats['start_time']:
                runtime = int((datetime.datetime.now() - self.stats['start_time']).total_seconds())
                self.stat_cards['Runtime']['value'].configure(text=f"{runtime}s")
            
            # Top Port
            if self.stats['port_activity']:
                top_port = max(self.stats['port_activity'].items(), key=lambda x: x[1])
                self.stat_cards['Top Port']['value'].configure(
                    text=f"{top_port[0]} ({top_port[1]})"
                )
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update)
        else:
            update()
    
    def check_network_connections(self):
        """Check network connections for suspicious activity"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    if remote_ip in ['0.0.0.0', '::', '127.0.0.1', '::1']:
                        continue
                    
                    # Update statistics
                    self.stats['total_connections'] += 1
                    
                    if remote_ip not in self.stats['unique_ips']:
                        self.stats['unique_ips'][remote_ip] = {
                            'ports': set(),
                            'count': 0,
                            'first_seen': datetime.datetime.now()
                        }
                    
                    self.stats['unique_ips'][remote_ip]['count'] += 1
                    self.stats['unique_ips'][remote_ip]['ports'].add(remote_port)
                    self.stats['port_activity'][remote_port] += 1
                    
                    # Check for suspicious ports
                    if remote_port in self.signature_rules['suspicious_ports']['ports']:
                        self.add_alert(
                            'Suspicious Port',
                            remote_ip,
                            f"Connection to port {remote_port} from {remote_ip}",
                            'MEDIUM',
                            'Network'
                        )
                        self.write_log(f"NETWORK ALERT: Suspicious Port - {remote_ip}:{remote_port}", "ALERT")
                    
                    # Check for port scanning
                    port_count = len(self.stats['unique_ips'][remote_ip]['ports'])
                    if port_count > self.signature_rules['port_scan']['threshold']:
                        cache_key = f"portscan_{remote_ip}_{port_count}"
                        if cache_key not in self.stats['processed_events']:
                            self.stats['processed_events'][cache_key] = datetime.datetime.now()
                            
                            self.add_alert(
                                'Port Scan',
                                remote_ip,
                                f"Possible port scan - accessed {port_count} different ports",
                                'HIGH',
                                'Network'
                            )
                            self.write_log(f"NETWORK ALERT: Port Scan - {remote_ip}", "ALERT")
        
        except Exception as e:
            self.write_log(f"Error checking network connections: {e}", "ERROR")
    
    def check_windows_events(self):
        """Check Windows Event Logs for security events (Windows only)"""
        if sys.platform != 'win32':
            return
        
        try:
            # Check for failed logons (Event ID 4625)
            self.check_failed_logons()
            
            # Check for other security events
            self.check_security_events()
            
        except Exception as e:
            self.write_log(f"Error checking Windows events: {e}", "WARNING")
    
    def check_failed_logons(self):
        """Check for failed logon attempts"""
        if sys.platform != 'win32':
            return
        
        try:
            server = 'localhost'
            logtype = 'Security'
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            
            failed_logons = defaultdict(list)
            events_checked = 0
            max_events = 100  # Limit to last 100 events
            
            while events_checked < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                
                for event in events:
                    events_checked += 1
                    
                    # Check if event is recent (last 5 minutes)
                    event_time = event.TimeGenerated
                    if (datetime.datetime.now() - event_time).total_seconds() > 300:
                        continue
                    
                    if event.EventID == 4625:  # Failed logon
                        # Parse event data
                        event_data = win32evtlogutil.SafeFormatMessage(event, logtype)
                        
                        # Extract source IP (simplified - would need proper parsing)
                        source_ip = "Local"
                        
                        failed_logons[source_ip].append({
                            'time': event_time,
                            'record_id': event.RecordNumber
                        })
                
                if events_checked >= max_events:
                    break
            
            win32evtlog.CloseEventLog(hand)
            
            # Check if any source exceeds threshold
            threshold = self.signature_rules['failed_logon']['threshold']
            
            for source_ip, events in failed_logons.items():
                if len(events) >= threshold:
                    # Use latest record ID in cache key
                    latest_record = max(events, key=lambda x: x['record_id'])['record_id']
                    cache_key = f"4625_{source_ip}_{latest_record}"
                    
                    # Check if already processed
                    if cache_key in self.stats['processed_events']:
                        cache_time = self.stats['processed_events'][cache_key]
                        if (datetime.datetime.now() - cache_time).total_seconds() < 300:
                            continue
                    
                    self.stats['processed_events'][cache_key] = datetime.datetime.now()
                    
                    self.add_alert(
                        'Brute Force Login',
                        source_ip,
                        f"{len(events)} failed logon attempts detected",
                        'HIGH',
                        'EventLog'
                    )
                    self.write_log(f"EVENT LOG ALERT: Brute Force Login - {source_ip}", "ALERT")
        
        except Exception as e:
            self.write_log(f"Error checking failed logons: {e}", "WARNING")
    
    def check_security_events(self):
        """Check for other security events"""
        if sys.platform != 'win32':
            return
        
        try:
            server = 'localhost'
            logtype = 'Security'
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events_to_check = [4740, 1102, 4720, 4726, 4732, 4719]
            events_checked = 0
            max_events = 50
            
            while events_checked < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                
                for event in events:
                    events_checked += 1
                    
                    # Check if event is recent
                    event_time = event.TimeGenerated
                    if (datetime.datetime.now() - event_time).total_seconds() > 300:
                        continue
                    
                    if event.EventID in events_to_check:
                        cache_key = f"{event.EventID}_{event.RecordNumber}"
                        
                        if cache_key not in self.stats['processed_events']:
                            self.stats['processed_events'][cache_key] = datetime.datetime.now()
                            
                            severity = 'HIGH' if event.EventID in [1102, 4740, 4719] else 'MEDIUM'
                            description = self.event_signatures.get(event.EventID, f"Event ID {event.EventID}")
                            
                            self.add_alert(
                                description,
                                'SYSTEM',
                                f"Event ID {event.EventID} detected",
                                severity,
                                'EventLog'
                            )
                            self.write_log(f"EVENT LOG ALERT: {description}", "ALERT")
                
                if events_checked >= max_events:
                    break
            
            win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            self.write_log(f"Error checking security events: {e}", "WARNING")
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        self.write_log("Monitoring started", "INFO")
        self.update_activity_log("=== Monitoring Started ===", "INFO")
        
        event_check_interval = 10  # Check events every 10 seconds
        last_event_check = time.time()
        
        while not self.stop_monitoring.is_set():
            try:
                # Check network connections
                self.check_network_connections()
                
                # Check Windows events (every 10 seconds)
                current_time = time.time()
                if current_time - last_event_check >= event_check_interval:
                    self.check_windows_events()
                    last_event_check = current_time
                
                # Update GUI
                self.update_stats_display()
                
                # Sleep
                time.sleep(2)
            
            except Exception as e:
                self.write_log(f"Error in monitoring loop: {e}", "ERROR")
                time.sleep(2)
        
        self.write_log("Monitoring stopped", "INFO")
        self.update_activity_log("=== Monitoring Stopped ===", "INFO")
    
    def start_monitoring(self):
        """Start monitoring"""
        if self.stats['is_monitoring']:
            return
        
        # Reset statistics
        self.stats = {
            'total_connections': 0,
            'unique_ips': {},
            'port_activity': defaultdict(int),
            'alerts': [],
            'start_time': datetime.datetime.now(),
            'is_monitoring': True,
            'network_alerts': 0,
            'event_alerts': 0,
            'last_event_check': datetime.datetime.now(),
            'processed_events': {}
        }
        
        # Update UI
        self.status_label.configure(text=" STATUS: MONITORING", fg='lime green')
        self.status_indicator.delete('all')
        self.status_indicator.create_oval(2, 2, 13, 13, fill='lime green', outline='white')
        
        self.buttons['Start Monitoring'].configure(state='disabled')
        self.buttons['Stop Monitoring'].configure(state='normal')
        
        # Start monitoring thread
        self.stop_monitoring.clear()
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        self.update_activity_log(f"Monitoring started at {datetime.datetime.now().strftime('%H:%M:%S')}", "INFO")
    
    def stop_monitoring_action(self):
        """Stop monitoring"""
        if not self.stats['is_monitoring']:
            return
        
        self.stats['is_monitoring'] = False
        self.stop_monitoring.set()
        
        # Update UI
        self.status_label.configure(text=" STATUS: STOPPED", fg='white')
        self.status_indicator.delete('all')
        self.status_indicator.create_oval(2, 2, 13, 13, fill='red', outline='white')
        
        self.buttons['Start Monitoring'].configure(state='normal')
        self.buttons['Stop Monitoring'].configure(state='disabled')
        
        self.update_activity_log(f"Monitoring stopped at {datetime.datetime.now().strftime('%H:%M:%S')}", "INFO")
    
    def clear_alerts(self):
        """Clear all alerts"""
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        
        self.write_log("Alerts cleared", "INFO")
    
    def export_logs(self):
        """Export logs to file"""
        try:
            export_path = self.log_path / f"IDS_Export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(export_path, 'w', encoding='utf-8') as f:
                f.write("=== ENHANCED IDS MONITORING REPORT ===\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write(f"Monitoring Period: {self.stats['start_time']} to {datetime.datetime.now()}\n\n")
                
                f.write("=== SUMMARY STATISTICS ===\n")
                f.write(f"Total Network Connections: {self.stats['total_connections']}\n")
                f.write(f"Unique IP Addresses: {len(self.stats['unique_ips'])}\n")
                f.write(f"Network Alerts: {self.stats['network_alerts']}\n")
                f.write(f"Event Log Alerts: {self.stats['event_alerts']}\n")
                f.write(f"Total Alerts: {len(self.stats['alerts'])}\n\n")
                
                f.write("=== NETWORK STATISTICS ===\n")
                f.write("Top 5 Active Ports:\n")
                if self.stats['port_activity']:
                    top_ports = sorted(self.stats['port_activity'].items(), key=lambda x: x[1], reverse=True)[:5]
                    for port, count in top_ports:
                        f.write(f"  Port {port}: {count} connections\n")
                else:
                    f.write("  No port activity recorded\n")
                
                f.write("\n=== RECENT ALERTS ===\n")
                for alert in self.stats['alerts'][:20]:
                    f.write(f"[{alert['time']}] [{alert['source']}] {alert['severity']} | {alert['type']} | {alert['details']}\n")
                
                f.write(f"\n=== LOG FILES ===\n")
                f.write(f"- Main Log: {self.log_file}\n")
                f.write(f"- Alert Log: {self.alert_file}\n")
            
            messagebox.showinfo(
                "Export Complete",
                f"Report exported successfully to:\n{export_path}\n\nWould you like to open it?"
            )
            
            # Open file
            if sys.platform == 'win32':
                os.startfile(export_path)
            elif sys.platform == 'darwin':
                os.system(f'open "{export_path}"')
            else:
                os.system(f'xdg-open "{export_path}"')
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs:\n{e}")
            self.write_log(f"Export failed: {e}", "ERROR")
    
    def show_settings(self):
        """Show settings dialog"""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("IDS Settings")
        settings_win.geometry("520x450")
        settings_win.resizable(False, False)
        
        tk.Label(
            settings_win,
            text="Detection Threshold Settings",
            font=('Segoe UI', 12, 'bold')
        ).pack(pady=20)
        
        # Port Scan Threshold
        frame1 = tk.Frame(settings_win)
        frame1.pack(fill=tk.X, padx=40, pady=10)
        
        tk.Label(frame1, text="Port Scan Threshold:", width=25, anchor='w').pack(side=tk.LEFT)
        port_scan_var = tk.IntVar(value=self.signature_rules['port_scan']['threshold'])
        tk.Spinbox(frame1, from_=5, to=100, textvariable=port_scan_var, width=10).pack(side=tk.LEFT)
        
        # Brute Force Threshold
        frame2 = tk.Frame(settings_win)
        frame2.pack(fill=tk.X, padx=40, pady=10)
        
        tk.Label(frame2, text="Brute Force Threshold:", width=25, anchor='w').pack(side=tk.LEFT)
        brute_force_var = tk.IntVar(value=self.signature_rules['brute_force']['threshold'])
        tk.Spinbox(frame2, from_=3, to=50, textvariable=brute_force_var, width=10).pack(side=tk.LEFT)
        
        # Failed Logon Threshold
        frame3 = tk.Frame(settings_win)
        frame3.pack(fill=tk.X, padx=40, pady=10)
        
        tk.Label(frame3, text="Failed Logon Threshold:", width=25, anchor='w').pack(side=tk.LEFT)
        failed_logon_var = tk.IntVar(value=self.signature_rules['failed_logon']['threshold'])
        tk.Spinbox(frame3, from_=3, to=20, textvariable=failed_logon_var, width=10).pack(side=tk.LEFT)
        
        # Info text
        info_text = """Monitored Event IDs:
• 4625 (Failed Logon)
• 4740 (Account Lockout)
• 1102 (Audit Log Cleared)
• 4720/4726 (User Create/Delete)
• 4732 (Group Membership Change)
• 4719 (Audit Policy Change)"""
        
        tk.Label(
            settings_win,
            text=info_text,
            justify=tk.LEFT,
            fg='gray'
        ).pack(pady=20)
        
        # Save button
        def save_settings():
            self.signature_rules['port_scan']['threshold'] = port_scan_var.get()
            self.signature_rules['brute_force']['threshold'] = brute_force_var.get()
            self.signature_rules['failed_logon']['threshold'] = failed_logon_var.get()
            
            self.write_log(
                f"Settings updated: PortScan={port_scan_var.get()}, "
                f"BruteForce={brute_force_var.get()}, FailedLogon={failed_logon_var.get()}",
                "INFO"
            )
            
            settings_win.destroy()
        
        btn_frame = tk.Frame(settings_win)
        btn_frame.pack(pady=20)
        
        tk.Button(
            btn_frame,
            text="Save Settings",
            command=save_settings,
            bg='#0078d7',
            fg='white',
            width=15,
            height=2
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            btn_frame,
            text="Cancel",
            command=settings_win.destroy,
            bg='#c8c8c8',
            width=15,
            height=2
        ).pack(side=tk.LEFT, padx=10)
    
    def run(self):
        """Run the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window close"""
        if self.stats['is_monitoring']:
            if messagebox.askokcancel("Quit", "Monitoring is active. Do you want to quit?"):
                self.stop_monitoring_action()
                time.sleep(0.5)
                self.root.destroy()
        else:
            self.root.destroy()


def check_admin():
    """Check if running with admin privileges (Windows)"""
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True


def main():
    """Main entry point"""
    # Check for pywin32 installation on Windows
    if sys.platform == 'win32':
        try:
            import win32evtlog
        except ImportError:
            print("ERROR: pywin32 not properly installed")
            print("Please run: python -m pip install pywin32")
            print("Then run: python Scripts/pywin32_postinstall.py -install")
            input("Press Enter to exit...")
            return
    
    if not check_admin():
        print("WARNING: Not running as administrator.")
        print("Some features (Event Log monitoring) may not work correctly.")
        print("Please run as administrator for full functionality.")
        input("Press Enter to continue anyway...")
    
    try:
        app = NetworkIDS()
        app.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()
