from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress
import os
try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Fallback for older Python
import tomli_w

# Track unique ports accessed per IP over time window
ip_activity = defaultdict(lambda: {
    "unique_ports": set(),
    "first_seen": None,
    "last_seen": None,
    "block_count": 0  # Track how many times this IP has been blocked
})

# Track access attempts per port (for distributed attack protection)
port_access_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# Thresholds and timing
UNIQUE_PORTS_THRESHOLD = 7  # Block after scanning 7+ different ports
ACTIVITY_WINDOW = timedelta(hours=2)  # Track activity over 2 hours

# Progressive blocking durations
BLOCK_DURATIONS = [
    timedelta(minutes=10),  # First offense: 10 minutes
    timedelta(hours=2),     # Second offense: 2 hours
    timedelta(days=1),      # Third offense: 1 day
    timedelta(days=7)       # Fourth+ offense: 1 week
]

# Trusted IPs and subnets that will never be blocked (supports CIDR notation)
TRUSTED_IPS = {
    "192.168.1.1",
    "192.168.1.100",
    "127.0.0.1",
    "192.168.0.0/16",  # Corporate subnet example
    "10.0.0.0/8"       # Private network example
}

# Port-specific thresholds for distributed attack detection
PORT_THRESHOLDS = {
    80: 2,      # Web server - stricter
    443: 2,     # HTTPS - stricter
    22: 3,      # SSH - moderate
    8000: 10,   # Development server - lenient
    8080: 10,   # Alternative HTTP - lenient
    3306: 5,    # MySQL - moderate
    5432: 5,    # PostgreSQL - moderate
}

# Default threshold for ports not specified above
DEFAULT_PORT_THRESHOLD = 10

# Configuration and state files
CONFIG_FILE = "firewall_config.toml"
STATE_FILE = "firewall_state.toml"

def parse_duration(duration_str):
    """Parse duration string like '10m', '2h', '1d' into timedelta."""
    if not duration_str:
        return timedelta(minutes=10)

    unit = duration_str[-1].lower()
    try:
        value = int(duration_str[:-1])
        if unit == 'm':
            return timedelta(minutes=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        else:
            return timedelta(minutes=10)  # Default fallback
    except ValueError:
        return timedelta(minutes=10)  # Default fallback

def load_config():
    """Load configuration from TOML file."""
    global UNIQUE_PORTS_THRESHOLD, ACTIVITY_WINDOW, BLOCK_DURATIONS
    global PORT_THRESHOLDS, DEFAULT_PORT_THRESHOLD, TRUSTED_IPS, STATE_FILE

    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'rb') as f:
                config = tomllib.load(f)

            # Get selected mode
            mode = config.get("firewall", {}).get("mode", "standard")
            print(f"Loading firewall configuration: {mode} mode")

            # Load mode-specific settings
            if mode in ["aggressive", "standard", "lenient"]:
                mode_config = config.get("modes", {}).get(mode, {})
            elif mode == "custom":
                mode_config = config.get("custom", {})
            else:
                print(f"Unknown mode '{mode}', using standard mode")
                mode_config = config.get("modes", {}).get("standard", {})

            # Update global settings
            UNIQUE_PORTS_THRESHOLD = mode_config.get("unique_ports_threshold", 7)
            DEFAULT_PORT_THRESHOLD = mode_config.get("default_port_threshold", 10)

            # Parse activity window
            activity_hours = mode_config.get("activity_window_hours", 2)
            ACTIVITY_WINDOW = timedelta(hours=activity_hours)

            # Parse block durations
            duration_strings = mode_config.get("block_durations", ["10m", "2h", "1d", "7d"])
            BLOCK_DURATIONS = [parse_duration(d) for d in duration_strings]

            # Update port thresholds
            port_thresholds = mode_config.get("port_thresholds", {})
            if port_thresholds:
                PORT_THRESHOLDS.update(port_thresholds)

            # Update trusted IPs and networks
            trusted = config.get("trusted", {})
            trusted_ips = set(trusted.get("ips", []))
            trusted_networks = set(trusted.get("networks", []))
            TRUSTED_IPS = trusted_ips.union(trusted_networks)

            # Update state file location
            STATE_FILE = config.get("firewall", {}).get("state_file", "firewall_state.toml")

            print(f"Configuration loaded: {UNIQUE_PORTS_THRESHOLD} port threshold, {len(TRUSTED_IPS)} trusted entries")

        else:
            print(f"No config file found at {CONFIG_FILE}, using defaults")

    except Exception as e:
        print(f"Error loading config: {e}, using defaults")

def is_ip_blocked(ip):
    """Check if the IP is already blocked in iptables."""
    result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
    return ip in result.stdout

def save_state():
    """Save current state to TOML file."""
    try:
        state = {}

        # Save IP activity data
        if ip_activity:
            state["ip_activity"] = {}
            for ip, data in ip_activity.items():
                state["ip_activity"][ip] = {
                    "unique_ports": list(data["unique_ports"]),
                    "first_seen": data["first_seen"].isoformat() if data["first_seen"] else "",
                    "last_seen": data["last_seen"].isoformat() if data["last_seen"] else "",
                    "block_count": data["block_count"]
                }

        # Save port access tracker
        if port_access_tracker:
            state["port_access_tracker"] = {}
            for port, data in port_access_tracker.items():
                state["port_access_tracker"][str(port)] = {
                    "count": data["count"],
                    "timestamp": data["timestamp"].isoformat() if data["timestamp"] else ""
                }

        # Save unblock tasks
        if sniff_thread.unblock_tasks:
            state["unblock_tasks"] = []
            for task in sniff_thread.unblock_tasks:
                state["unblock_tasks"].append({
                    "ip": task["ip"],
                    "unblock_time": task["unblock_time"].isoformat()
                })

        with open(STATE_FILE, 'wb') as f:
            tomli_w.dump(state, f)
    except Exception as e:
        print(f"Error saving state: {e}")

def load_state():
    """Load state from TOML file."""
    global ip_activity, port_access_tracker
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'rb') as f:
                state = tomllib.load(f)

            # Restore ip_activity
            for ip, data in state.get("ip_activity", {}).items():
                ip_activity[ip] = {
                    "unique_ports": set(data["unique_ports"]),
                    "first_seen": datetime.fromisoformat(data["first_seen"]) if data["first_seen"] else None,
                    "last_seen": datetime.fromisoformat(data["last_seen"]) if data["last_seen"] else None,
                    "block_count": data["block_count"]
                }

            # Restore port_access_tracker
            for port, data in state.get("port_access_tracker", {}).items():
                port_access_tracker[int(port)] = {
                    "count": data["count"],
                    "timestamp": datetime.fromisoformat(data["timestamp"]) if data["timestamp"] else None
                }

            # Restore unblock_tasks
            for task in state.get("unblock_tasks", []):
                sniff_thread.unblock_tasks.append({
                    "ip": task["ip"],
                    "unblock_time": datetime.fromisoformat(task["unblock_time"])
                })

            print(f"State loaded: {len(ip_activity)} IPs, {len(port_access_tracker)} ports, {len(sniff_thread.unblock_tasks)} unblock tasks")
    except Exception as e:
        print(f"Error loading state: {e}")

def block_ip(ip):
    """Block the given IP using iptables."""
    if is_ip_blocked(ip):
        print(f"IP {ip} is already blocked. Skipping...")
        return

    print(f"Blocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        save_state()
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")
        print("Firewall state saved for recovery")
        save_state()

def unblock_ip(ip):
    """Unblock the given IP."""
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        save_state()
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")
        print("Firewall state saved for recovery")
        save_state()

def is_trusted_ip(ip):
    """Check if IP is in trusted list (supports both individual IPs and CIDR subnets)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for trusted in TRUSTED_IPS:
            if '/' in trusted:  # CIDR subnet
                if ip_obj in ipaddress.ip_network(trusted, strict=False):
                    return True
            else:  # Individual IP
                if ip == trusted:
                    return True
        return False
    except ValueError:
        return False

def handle_packet(packet):
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag detected
        src_ip = packet[IP].src
        port = packet[TCP].dport
        src_port = packet[TCP].sport

        # Check if IP is in trusted list or subnet - skip all processing if it is
        if is_trusted_ip(src_ip):
            print(f"✅ Trusted IP {src_ip} accessing port {port} - allowing")
        else:
            print(f"🔍 Access detected on port {port} from {src_ip}")

            # Track unique port access
            current_time = datetime.now()
            activity = ip_activity[src_ip]

            # Reset activity if outside time window
            if activity["first_seen"] and current_time - activity["first_seen"] > ACTIVITY_WINDOW:
                ip_activity[src_ip] = {
                    "unique_ports": {port},
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "block_count": activity["block_count"]  # Preserve block count for progressive blocking
                }
            else:
                # Update activity
                if not activity["first_seen"]:
                    activity["first_seen"] = current_time
                activity["unique_ports"].add(port)
                activity["last_seen"] = current_time

            # Track port access attempts (distributed attack protection)
            if port_access_tracker[port]["timestamp"] and current_time - port_access_tracker[port]["timestamp"] > ACTIVITY_WINDOW:
                # Reset port tracker after activity window
                port_access_tracker[port] = {"count": 0, "timestamp": None}

            port_access_tracker[port]["count"] += 1
            port_access_tracker[port]["timestamp"] = current_time

            # Check for distributed attack on sensitive ports
            port_threshold = PORT_THRESHOLDS.get(port, DEFAULT_PORT_THRESHOLD)
            if port_access_tracker[port]["count"] > port_threshold:
                print(f"🚫 Port {port} under distributed attack ({port_access_tracker[port]['count']} > {port_threshold} attempts), blocking IP {src_ip}...")
                block_ip(src_ip)
                # Schedule unblock (use first offense duration for port-based blocks)
                unblock_time = datetime.now() + BLOCK_DURATIONS[0]
                print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
                sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
                return

            # Block if scanning multiple unique ports
            unique_port_count = len(activity["unique_ports"])
            if unique_port_count > UNIQUE_PORTS_THRESHOLD:
                # Progressive blocking - get duration based on offense count
                block_count = activity["block_count"]
                duration_index = min(block_count, len(BLOCK_DURATIONS) - 1)
                block_duration = BLOCK_DURATIONS[duration_index]

                # Increment block count for this IP
                activity["block_count"] += 1

                print(f"🚫 IP {src_ip} scanned {unique_port_count} unique ports (offense #{activity['block_count']}), blocking for {block_duration}...")
                block_ip(src_ip)
                # Schedule unblock
                unblock_time = datetime.now() + block_duration
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
            save_state()  # Save state after removing unblock task

class SniffThread:
    def __init__(self):
        self.unblock_tasks = []

    def start_sniffing(self):
        sniff(filter="tcp", prn=handle_packet)

sniff_thread = SniffThread()

if __name__ == "__main__":
    import threading
    import time

    # Load configuration first
    load_config()

    # Start the sniffing in a separate thread
    sniff_thread = SniffThread()
    load_state()  # Load persistent state on startup
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, daemon=True)
    sniff_thread_thread.start()

    # Get sleep interval from config
    sleep_interval = 5  # Default
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'rb') as f:
                config = tomllib.load(f)
            sleep_interval = config.get("firewall", {}).get("sleep_interval", 5)
    except:
        pass

    # Monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips()
            time.sleep(sleep_interval)
    except KeyboardInterrupt:
        print("\n🛑 Stopping firewall...")
        save_state()  # Save state on shutdown