#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import signal
import hashlib
from datetime import datetime, timedelta
from scapy.all import *

def is_process_alive(pid):
    """Check if a specific PID is still running."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)  # Signal 0 just checks if process exists
        return True
    except OSError:
        # Permission denied or process doesn't exist - fallback to pgrep
        return bool(get_firewall_pid())

def get_firewall_pid():
    """Get PID of running firewall.py process."""
    try:
        result = subprocess.run(["pgrep", "-f", "firewall.py"], stdout=subprocess.PIPE, text=True)
        pid_str = result.stdout.strip()
        return int(pid_str) if pid_str else None
    except:
        return None

def check_file_integrity():
    """Check if firewall.py has been tampered with."""
    try:
        with open("firewall.py", "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        # Try to read stored hash
        try:
            with open("firewall.py.sha256", "r") as f:
                stored_hash = f.read().strip()
            return current_hash == stored_hash
        except FileNotFoundError:
            # Create hash file if it doesn't exist
            with open("firewall.py.sha256", "w") as f:
                f.write(current_hash)
            print("Created integrity hash for firewall.py")
            return True
    except Exception as e:
        print(f"Integrity check failed: {e}")
        return False


def test_firewall_blocking():
    """Test if firewall blocks suspicious activity by sending test packets."""
    try:
        # Send packets from a test IP to multiple ports (should trigger blocking)
        test_ip = "1.2.3.4"  # Fake IP for testing
        ports = [80, 443, 22, 8000, 3306, 5432, 21, 25]  # 8 ports (exceeds threshold of 7)
        
        print(f"Testing firewall with packets from {test_ip} to {len(ports)} ports...")
        
        for port in ports:
            packet = IP(dst="127.0.0.1", src=test_ip) / TCP(dport=port, flags="S")
            send(packet, verbose=0)
            time.sleep(0.1)  # Small delay between packets
        
        time.sleep(2)  # Wait for firewall to process
        
        # Check if test IP got blocked in iptables
        result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
        is_blocked = test_ip in result.stdout
        
        # Clean up - remove test IP from iptables if it was blocked
        if is_blocked:
            try:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", test_ip, "-j", "DROP"], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except:
                pass
        
        return is_blocked
    except Exception as e:
        print(f"Error testing firewall: {e}")
        return False

def start_firewall():
    """Start the firewall process and return its PID."""
    try:
        print("Starting firewall...")
        process = subprocess.Popen([sys.executable, "firewall.py"],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        time.sleep(3)  # Give it time to start
        return process.pid
    except Exception as e:
        print(f"Error starting firewall: {e}")
        return None

def monitor_firewall():
    """Main monitoring function."""
    print("🔍 Firewall Monitor Started")
    last_functional_test = datetime.now() - timedelta(days=1)  # Force test on first run
    firewall_pid = get_firewall_pid()  # Get existing PID or None

    while True:
        try:
            # Security check: Verify firewall.py hasn't been tampered with
            if not check_file_integrity():
                print("🚨 SECURITY ALERT: firewall.py has been modified!")
                print("🛑 Stopping monitor for security reasons")
                sys.exit(1)
            # Primary check: Process running (every minute) - optimized with PID
            process_running = is_process_alive(firewall_pid)
            print(f"Process check (PID {firewall_pid}): {'✅ Running' if process_running else '❌ Not running'}")

            if not process_running:
                print("⚠️  Firewall process not found, starting...")
                firewall_pid = start_firewall()
                if firewall_pid:
                    print(f"✅ Firewall restarted (PID {firewall_pid})")
                else:
                    print("❌ Failed to start firewall")
                time.sleep(60)
                continue

            # Secondary check: Functional test (once per day)
            now = datetime.now()
            if now - last_functional_test >= timedelta(days=1):
                print("Running daily functional test...")
                is_blocking = test_firewall_blocking()
                print(f"Blocking test: {'✅ Working' if is_blocking else '❌ Not blocking'}")
                last_functional_test = now

                if not is_blocking:
                    print("⚠️  Firewall not blocking properly, restarting...")
                    try:
                        subprocess.run(["pkill", "-f", "firewall.py"])
                        time.sleep(2)
                    except:
                        pass

                    if start_firewall():
                        print("✅ Firewall restarted")
                    else:
                        print("❌ Failed to restart firewall")

            print("✅ Monitoring check complete\n")
            time.sleep(60)  # Check every minute

        except KeyboardInterrupt:
            print("\n🛑 Stopping firewall monitor...")
            break
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(30)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ This script requires root privileges (for iptables testing)")
        sys.exit(1)
    
    monitor_firewall()
