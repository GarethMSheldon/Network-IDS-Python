#!/usr/bin/env python3
"""
Test script for Network IDS
Generates test network connections and events
"""

import socket
import time
import sys
import subprocess
from datetime import datetime

def print_header(text):
    """Print formatted header"""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

def test_network_connections():
    """Generate test network connections"""
    print_header("Testing Network Connection Detection")
    
    test_hosts = [
        ('google.com', 80),
        ('github.com', 443),
        ('microsoft.com', 80),
    ]
    
    print("Generating test connections...")
    for host, port in test_hosts:
        try:
            print(f"  Connecting to {host}:{port}...", end=' ')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            print("✓ Success")
            sock.close()
            time.sleep(0.5)
        except Exception as e:
            print(f"✗ Failed: {e}")
    
    print("\n✓ Network connection test complete")

def test_suspicious_ports():
    """Test suspicious port detection"""
    print_header("Testing Suspicious Port Detection")
    
    suspicious_ports = [23, 445, 3389, 5900]
    test_host = 'scanme.nmap.org'  # Safe to scan
    
    print(f"Testing connections to suspicious ports on {test_host}...")
    for port in suspicious_ports:
        try:
            print(f"  Port {port}...", end=' ')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((test_host, port))
            if result == 0:
                print("✓ Connected (IDS should alert)")
            else:
                print("✗ Connection failed (expected)")
            sock.close()
            time.sleep(0.5)
        except Exception as e:
            print(f"✗ Error: {e}")
    
    print("\n✓ Suspicious port test complete")
    print("⚠ IDS should show 'Suspicious Port' alerts")

def test_port_scan():
    """Simulate port scan behavior"""
    print_header("Testing Port Scan Detection")
    
    test_host = 'scanme.nmap.org'
    ports = range(20, 35)  # Scan 15 ports
    
    print(f"Simulating port scan on {test_host}...")
    print(f"Scanning ports {min(ports)} to {max(ports)}...")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex((test_host, port))
            sock.close()
            print('.', end='', flush=True)
            time.sleep(0.1)
        except:
            pass
    
    print("\n\n✓ Port scan simulation complete")
    print("⚠ IDS should show 'Port Scan' alert (threshold: 10 ports)")

def test_failed_logons_windows():
    """Test failed logon detection (Windows only)"""
    if sys.platform != 'win32':
        print("\n⚠ Failed logon testing only available on Windows")
        return
    
    print_header("Testing Failed Logon Detection (Windows)")
    
    print("Generating failed logon attempts...")
    print("(This will create Event ID 4625 entries)")
    
    # PowerShell one-liner to generate failed logons
    ps_command = """
    1..6 | ForEach-Object {
        $pass = ConvertTo-SecureString "WrongPass$_" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("FakeUser$_", $pass)
        try { Start-Process cmd -Credential $cred -ErrorAction Stop } catch { }
    }
    """
    
    try:
        print("Running PowerShell command...")
        subprocess.run(
            ['powershell', '-Command', ps_command],
            capture_output=True,
            timeout=30
        )
        print("✓ Generated 6 failed logon attempts")
        print("⚠ IDS should show 'Brute Force Login' alert within 10 seconds")
    except Exception as e:
        print(f"✗ Error generating failed logons: {e}")
        print("\nAlternative: Run this in PowerShell as Administrator:")
        print('1..6 | ForEach-Object {')
        print('    $pass = ConvertTo-SecureString "Wrong$_" -AsPlainText -Force')
        print('    $cred = New-Object PSCredential("TestUser", $pass)')
        print('    try { Start-Process cmd -Credential $cred } catch { }')
        print('}')

def verify_requirements():
    """Verify Python dependencies"""
    print_header("Verifying Requirements")
    
    required = ['psutil']
    if sys.platform == 'win32':
        required.append('win32evtlog')
    
    missing = []
    for module in required:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} - NOT INSTALLED")
            missing.append(module)
    
    if missing:
        print(f"\n⚠ Missing modules: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False
    else:
        print("\n✓ All requirements satisfied")
        return True

def check_privileges():
    """Check if running with appropriate privileges"""
    print_header("Checking Privileges")
    
    if sys.platform == 'win32':
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✓ Running as Administrator")
                return True
            else:
                print("✗ NOT running as Administrator")
                print("⚠ Event log monitoring will not work")
                print("  Right-click and 'Run as Administrator'")
                return False
        except:
            print("⚠ Could not determine admin status")
            return False
    else:
        import os
        if os.geteuid() == 0:
            print("✓ Running as root/sudo")
            return True
        else:
            print("✗ NOT running as root")
            print("⚠ Some features may not work")
            print("  Run with: sudo python3 test_ids.py")
            return False

def show_menu():
    """Show test menu"""
    print_header("Network IDS Test Suite")
    print(f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Platform: {sys.platform}")
    print()
    print("1. Verify Requirements")
    print("2. Check Privileges")
    print("3. Test Network Connections")
    print("4. Test Suspicious Port Detection")
    print("5. Test Port Scan Detection")
    if sys.platform == 'win32':
        print("6. Test Failed Logon Detection (Windows)")
    print("7. Run All Tests")
    print("0. Exit")
    print()

def main():
    """Main function"""
    print_header("Network IDS Test Script")
    print("This script tests the IDS detection capabilities")
    print("Make sure the IDS is running and monitoring is started!")
    print()
    input("Press Enter to continue...")
    
    while True:
        show_menu()
        choice = input("Select option: ").strip()
        
        if choice == '0':
            print("\nExiting...")
            break
        elif choice == '1':
            verify_requirements()
        elif choice == '2':
            check_privileges()
        elif choice == '3':
            test_network_connections()
        elif choice == '4':
            test_suspicious_ports()
        elif choice == '5':
            test_port_scan()
        elif choice == '6' and sys.platform == 'win32':
            test_failed_logons_windows()
        elif choice == '7':
            print_header("Running All Tests")
            verify_requirements()
            check_privileges()
            test_network_connections()
            test_suspicious_ports()
            test_port_scan()
            if sys.platform == 'win32':
                test_failed_logons_windows()
            print_header("All Tests Complete")
            print("Check the IDS for alerts!")
        else:
            print("Invalid option")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
