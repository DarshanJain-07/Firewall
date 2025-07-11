from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

# Dictionary to track scan counts and timestamps
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# Dictionary to track access attempts per port
port_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# Duration to block an IP (10 minutes)
BLOCK_DURATION = timedelta(minutes=10)

# Trusted IPs that will never be blocked (add your trusted IPs here)
TRUSTED_IPS = {
    "192.168.1.1",
    "192.168.1.100",
    "127.0.0.1"     
}

def is_ip_blocked(ip):
    """Check if the IP is already blocked in iptables."""
    result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
    return ip in result.stdout

def block_ip(ip):
    """Block the given IP using iptables."""
    if is_ip_blocked(ip):
        print(f"IP {ip} is already blocked. Skipping...")
        return

    print(f"Blocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

def unblock_ip(ip):
    """Unblock the given IP."""
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")

def handle_packet(packet):
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag detected
        src_ip = packet[IP].src
        port = packet[TCP].dport
        src_port = packet[TCP].sport

        # Check if IP is in trusted list - skip all processing if it is
        if src_ip in TRUSTED_IPS:
            print(f"✅ Trusted IP {src_ip} accessing port {port} - allowing")
        else:
            print(f"🔍 Scan detected on port {port} from {src_ip}")

            # Check and update scan count
            current_time = datetime.now()
            if scan_tracker[src_ip]["timestamp"] and current_time - scan_tracker[src_ip]["timestamp"] > BLOCK_DURATION:
                # Reset tracker after block duration
                scan_tracker[src_ip] = {"count": 0, "timestamp": None}

            scan_tracker[src_ip]["count"] += 1
            scan_tracker[src_ip]["timestamp"] = current_time

            # Track port access attempts
            if port_tracker[port]["timestamp"] and current_time - port_tracker[port]["timestamp"] > BLOCK_DURATION:
                # Reset port tracker after block duration
                port_tracker[port] = {"count": 0, "timestamp": None}

            port_tracker[port]["count"] += 1
            port_tracker[port]["timestamp"] = current_time

            # Block if IP exceeds limit OR if port is under distributed attack
            if scan_tracker[src_ip]["count"] > 3:
                print(f"🚫 IP {src_ip} exceeded scan limit, blocking for 10 minutes...")
                block_ip(src_ip)
                # Schedule unblock
                unblock_time = datetime.now() + BLOCK_DURATION
                print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
                sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
                return
            elif port_tracker[port]["count"] > 10:  # Higher threshold for distributed attacks
                print(f"🚫 Port {port} under distributed attack ({port_tracker[port]['count']} attempts), blocking IP {src_ip}...")
                block_ip(src_ip)
                # Schedule unblock
                unblock_time = datetime.now() + BLOCK_DURATION
                print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
                sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
                return

        # Respond with SYN-ACK (for both trusted and non-blocked IPs)
        syn_ack = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
        )
        send(syn_ack, verbose=0)
        print(f"Sent SYN-ACK to {src_ip} on port {port}")

def unblock_expired_ips():
    """Unblock IPs whose block duration has expired."""
    now = datetime.now()
    for task in list(sniff_thread.unblock_tasks):
        if now >= task["unblock_time"]:
            unblock_ip(task["ip"])
            sniff_thread.unblock_tasks.remove(task)

class SniffThread:
    def __init__(self):
        self.unblock_tasks = []

    def start_sniffing(self):
        sniff(filter="tcp", prn=handle_packet)

sniff_thread = SniffThread()

if __name__ == "__main__":
    import threading
    import time

    # Start the sniffing in a separate thread
    sniff_thread = SniffThread()
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, daemon=True)
    sniff_thread_thread.start()

    # Monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n🛑 Stopping firewall...")