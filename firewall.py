from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress
import os
import queue
import threading
import json
import requests
import hashlib
import hmac
import time
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
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

# Port filtering for firewall replacement functionality
ALLOWED_PORTS = set()  # Ports that are allowed through firewall
FIREWALL_MODE = "detection_only"  # "detection_only", "firewall", "corporate"

# Configuration and state files
CONFIG_FILE = "firewall_config.toml"
STATE_FILE = "firewall_state.toml"

# Webhook configuration
WEBHOOK_CONFIG = {
    "enabled": False,
    "endpoints": [],
    "retry_attempts": 3,
    "retry_delay": 5,  # seconds
    "timeout": 10,  # seconds
    "batch_size": 10,  # events to batch together
    "batch_timeout": 30,  # seconds to wait before sending partial batch
    "rate_limit": 100,  # max requests per minute
    "signature_header": "X-Firewall-Signature",
    "timestamp_header": "X-Firewall-Timestamp"
}

# Webhook event queue and batching
webhook_queue = queue.Queue(maxsize=1000)
webhook_batch = []
last_batch_time = datetime.now()
webhook_rate_limiter = {"requests": 0, "window_start": datetime.now()}

# Fast path caches for high performance
blocked_ips_cache = set()  # Cache of currently blocked IPs
slow_path_queue = queue.Queue(maxsize=1000)  # Queue for complex analysis

# Periodic state saving configuration
state_save_intervals = {
    "aggressive": 30,   # 30 seconds - minimal data loss risk
    "standard": 120,    # 2 minutes - balanced
    "lenient": 300,     # 5 minutes - performance focused
    "custom": 120       # Default for custom mode
}
current_save_interval = 120  # Default
last_state_save = datetime.now()

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
    global current_save_interval, ALLOWED_PORTS, FIREWALL_MODE, WEBHOOK_CONFIG

    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'rb') as f:
                config = tomllib.load(f)

            # Get selected mode
            mode = config.get("firewall", {}).get("mode", "standard")
            print(f"Loading firewall configuration: {mode} mode")

            # Set state save interval based on mode
            current_save_interval = state_save_intervals.get(mode, 120)
            print(f"State save interval: {current_save_interval} seconds")

            # Load mode-specific settings
            if mode in ["aggressive", "standard", "lenient"]:
                mode_config = config.get("modes", {}).get(mode, {})
            elif mode == "custom":
                mode_config = config.get("custom", {})
                # Allow custom save interval override
                custom_save_interval = config.get("firewall", {}).get("state_save_interval")
                if custom_save_interval:
                    current_save_interval = custom_save_interval
                    print(f"Custom state save interval: {current_save_interval} seconds")
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

            # Load firewall mode and allowed ports
            FIREWALL_MODE = config.get("firewall", {}).get("firewall_mode", "detection_only")

            # Load allowed ports based on mode
            if FIREWALL_MODE in ["firewall", "corporate"]:
                allowed_ports_config = config.get("allowed_ports", {})
                tcp_ports = allowed_ports_config.get("tcp", [])
                ALLOWED_PORTS.clear()
                ALLOWED_PORTS.update(tcp_ports)
                print(f"Firewall mode: {FIREWALL_MODE}, allowed ports: {sorted(ALLOWED_PORTS) if ALLOWED_PORTS else 'ALL'}")
            else:
                ALLOWED_PORTS.clear()  # Detection only mode - all ports allowed
                print(f"Detection only mode: monitoring all ports")

            # Load webhook configuration
            webhook_config = config.get("webhooks", {})
            if webhook_config:
                WEBHOOK_CONFIG.update(webhook_config)
                print(f"Webhook configuration loaded: {len(WEBHOOK_CONFIG.get('endpoints', []))} endpoints")

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
        if hasattr(sniff_thread, 'unblock_tasks') and sniff_thread.unblock_tasks:
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
            if hasattr(sniff_thread, 'unblock_tasks'):
                for task in state.get("unblock_tasks", []):
                    sniff_thread.unblock_tasks.append({
                        "ip": task["ip"],
                        "unblock_time": datetime.fromisoformat(task["unblock_time"])
                    })

            # Rebuild blocked IPs cache from iptables
            rebuild_blocked_cache()

            print(f"State loaded: {len(ip_activity)} IPs, {len(port_access_tracker)} ports, {len(sniff_thread.unblock_tasks)} unblock tasks")
    except Exception as e:
        print(f"Error loading state: {e}")

def rebuild_blocked_cache():
    """Rebuild the blocked IPs cache from current iptables rules."""
    try:
        result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
        blocked_ips_cache.clear()
        for line in result.stdout.split('\n'):
            if 'DROP' in line and '-s' in line:
                # Extract IP from iptables rule
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == '-s' and i + 1 < len(parts):
                        ip = parts[i + 1].split('/')[0]  # Remove CIDR if present
                        blocked_ips_cache.add(ip)
        print(f"Rebuilt blocked IPs cache: {len(blocked_ips_cache)} IPs")
    except Exception as e:
        print(f"Error rebuilding blocked cache: {e}")

def block_ip(ip, reason="port_scanning", additional_data=None):
    """Block the given IP using iptables."""
    if ip in blocked_ips_cache:
        print(f"IP {ip} is already blocked. Skipping...")
        return

    print(f"Blocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips_cache.add(ip)  # Update cache

        # Queue webhook event
        webhook_data = {
            "ip": ip,
            "reason": reason,
            "action": "blocked",
            "method": "iptables",
            "block_count": ip_activity[ip]["block_count"] if ip in ip_activity else 0
        }
        if additional_data:
            webhook_data.update(additional_data)

        queue_webhook_event("ip_blocked", webhook_data)

        # No immediate save_state() - handled by periodic saves
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

        # Queue webhook event for error
        queue_webhook_event("block_error", {
            "ip": ip,
            "reason": reason,
            "error": str(e),
            "action": "block_failed"
        })

        # Force immediate save on error for recovery
        save_state()

def unblock_ip(ip, reason="timeout_expired"):
    """Unblock the given IP."""
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips_cache.discard(ip)  # Update cache

        # Queue webhook event
        queue_webhook_event("ip_unblocked", {
            "ip": ip,
            "reason": reason,
            "action": "unblocked",
            "method": "iptables"
        })

        # No immediate save_state() - handled by periodic saves
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")

        # Queue webhook event for error
        queue_webhook_event("unblock_error", {
            "ip": ip,
            "reason": reason,
            "error": str(e),
            "action": "unblock_failed"
        })

        # Force immediate save on error for recovery
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

def create_webhook_signature(payload: str, secret: str) -> str:
    """Create HMAC-SHA256 signature for webhook payload."""
    return hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def create_webhook_event(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a standardized webhook event."""
    return {
        "id": hashlib.md5(f"{event_type}_{time.time()}_{data}".encode()).hexdigest(),
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "version": "1.0",
        "source": "firewall",
        "data": data
    }

def queue_webhook_event(event_type: str, data: Dict[str, Any]):
    """Queue a webhook event for delivery."""
    if not WEBHOOK_CONFIG.get("enabled", False):
        return

    event = create_webhook_event(event_type, data)
    try:
        webhook_queue.put_nowait(event)
    except queue.Full:
        print(f"⚠️ Webhook queue full, dropping event: {event_type}")

def check_rate_limit() -> bool:
    """Check if we're within rate limits."""
    now = datetime.now()
    window_duration = timedelta(minutes=1)

    # Reset window if needed
    if now - webhook_rate_limiter["window_start"] > window_duration:
        webhook_rate_limiter["requests"] = 0
        webhook_rate_limiter["window_start"] = now

    # Check if we're under the limit
    if webhook_rate_limiter["requests"] >= WEBHOOK_CONFIG.get("rate_limit", 100):
        return False

    webhook_rate_limiter["requests"] += 1
    return True

async def send_webhook_batch(session: aiohttp.ClientSession, endpoint: Dict[str, str], events: List[Dict[str, Any]]):
    """Send a batch of webhook events to an endpoint."""
    if not check_rate_limit():
        print(f"⚠️ Rate limit exceeded, skipping webhook to {endpoint['url']}")
        return False

    payload = {
        "events": events,
        "batch_size": len(events),
        "timestamp": datetime.now().isoformat()
    }

    payload_json = json.dumps(payload, sort_keys=True)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Firewall-Webhook/1.0"
    }

    # Add signature if secret is provided
    if endpoint.get("secret"):
        signature = create_webhook_signature(payload_json, endpoint["secret"])
        headers[WEBHOOK_CONFIG.get("signature_header", "X-Firewall-Signature")] = f"sha256={signature}"

    # Add timestamp header
    headers[WEBHOOK_CONFIG.get("timestamp_header", "X-Firewall-Timestamp")] = str(int(time.time()))

    # Add custom headers
    if endpoint.get("headers"):
        headers.update(endpoint["headers"])

    retry_attempts = WEBHOOK_CONFIG.get("retry_attempts", 3)
    retry_delay = WEBHOOK_CONFIG.get("retry_delay", 5)

    for attempt in range(retry_attempts):
        try:
            timeout = aiohttp.ClientTimeout(total=WEBHOOK_CONFIG.get("timeout", 10))
            async with session.post(
                endpoint["url"],
                data=payload_json,
                headers=headers,
                timeout=timeout
            ) as response:
                if response.status == 200:
                    print(f"✅ Webhook delivered to {endpoint['url']} ({len(events)} events)")
                    return True
                else:
                    print(f"⚠️ Webhook failed to {endpoint['url']}: HTTP {response.status}")

        except Exception as e:
            print(f"⚠️ Webhook error to {endpoint['url']} (attempt {attempt + 1}): {e}")

        if attempt < retry_attempts - 1:
            await asyncio.sleep(retry_delay)

    print(f"❌ Webhook failed to {endpoint['url']} after {retry_attempts} attempts")
    return False

async def process_webhook_queue():
    """Process webhook events from the queue."""
    global webhook_batch, last_batch_time

    if not WEBHOOK_CONFIG.get("enabled", False) or not WEBHOOK_CONFIG.get("endpoints"):
        return

    batch_size = WEBHOOK_CONFIG.get("batch_size", 10)
    batch_timeout = WEBHOOK_CONFIG.get("batch_timeout", 30)

    # Collect events from queue
    events_to_process = []
    try:
        while len(events_to_process) < batch_size:
            event = webhook_queue.get_nowait()
            events_to_process.append(event)
    except queue.Empty:
        pass

    # Add to current batch
    webhook_batch.extend(events_to_process)

    # Check if we should send the batch
    now = datetime.now()
    should_send = (
        len(webhook_batch) >= batch_size or
        (webhook_batch and (now - last_batch_time).total_seconds() >= batch_timeout)
    )

    if should_send and webhook_batch:
        events_to_send = webhook_batch.copy()
        webhook_batch.clear()
        last_batch_time = now

        # Send to all endpoints
        async with aiohttp.ClientSession() as session:
            tasks = []
            for endpoint in WEBHOOK_CONFIG.get("endpoints", []):
                if endpoint.get("url"):
                    task = send_webhook_batch(session, endpoint, events_to_send)
                    tasks.append(task)

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

def handle_packet(packet):
    """Fast path packet handler - immediate decisions only."""
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag detected
        src_ip = packet[IP].src
        port = packet[TCP].dport
        src_port = packet[TCP].sport

        # FAST PATH: Immediate decisions
        # 1. Check if IP is trusted (fastest check)
        if is_trusted_ip(src_ip):
            # For trusted IPs, check port filtering in firewall modes
            if FIREWALL_MODE in ["firewall", "corporate"] and port not in ALLOWED_PORTS:
                print(f"🚫 Trusted IP {src_ip} accessing blocked port {port} - dropping")
                return  # Drop even trusted IPs on blocked ports

            print(f"✅ Trusted IP {src_ip} accessing port {port} - allowing")
            # Send SYN-ACK immediately for trusted IPs on allowed ports
            syn_ack = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
            )
            send(syn_ack, verbose=0)
            return

        # 2. Check if IP is already blocked (fast cache lookup)
        if src_ip in blocked_ips_cache:
            print(f"� Already blocked IP {src_ip} trying port {port} - dropping")
            return  # Drop packet, no response

        # 3. Firewall port filtering (critical security check)
        if FIREWALL_MODE in ["firewall", "corporate"] and port not in ALLOWED_PORTS:
            print(f"🚫 Port {port} not allowed, dropping packet from {src_ip}")
            return  # Drop packet silently - firewall behavior

        # SLOW PATH: Queue for complex analysis (only for allowed ports)
        try:
            slow_path_queue.put_nowait({
                "src_ip": src_ip,
                "port": port,
                "src_port": src_port,
                "packet": packet,
                "timestamp": datetime.now()
            })
        except queue.Full:
            print(f"⚠️ Slow path queue full, dropping packet from {src_ip}")

def process_slow_path():
    """Slow path processor - complex analysis in separate thread."""
    while True:
        try:
            # Get packet from queue (blocks until available)
            packet_data = slow_path_queue.get()
            src_ip = packet_data["src_ip"]
            port = packet_data["port"]
            src_port = packet_data["src_port"]
            packet = packet_data["packet"]
            current_time = packet_data["timestamp"]

            print(f"🔍 Analyzing {src_ip} accessing port {port}")

            # Queue webhook event for connection attempt
            queue_webhook_event("connection_attempt", {
                "ip": src_ip,
                "port": port,
                "src_port": src_port,
                "timestamp": current_time.isoformat()
            })

            # Track unique port access
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

                # Queue webhook event for distributed attack detection
                queue_webhook_event("distributed_attack_detected", {
                    "ip": src_ip,
                    "port": port,
                    "attempts": port_access_tracker[port]["count"],
                    "threshold": port_threshold,
                    "attack_type": "distributed_port_attack"
                })

                block_ip(src_ip, "distributed_attack", {
                    "port": port,
                    "attempts": port_access_tracker[port]["count"],
                    "threshold": port_threshold
                })

                # Schedule unblock (use first offense duration for port-based blocks)
                unblock_time = datetime.now() + BLOCK_DURATIONS[0]
                print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
                sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
                slow_path_queue.task_done()
                continue

            # Block if scanning multiple unique ports
            unique_port_count = len(activity["unique_ports"])
            if unique_port_count > UNIQUE_PORTS_THRESHOLD:
                # Progressive blocking - get duration based on offense count
                block_count = activity["block_count"]
                duration_index = min(block_count, len(BLOCK_DURATIONS) - 1)
                block_duration = BLOCK_DURATIONS[duration_index]

                # Increment block count for this IP
                activity["block_count"] += 1

                # Queue webhook event for port scanning detection
                queue_webhook_event("port_scanning_detected", {
                    "ip": src_ip,
                    "unique_ports_scanned": unique_port_count,
                    "threshold": UNIQUE_PORTS_THRESHOLD,
                    "ports": list(activity["unique_ports"]),
                    "offense_count": activity["block_count"],
                    "block_duration_seconds": int(block_duration.total_seconds()),
                    "attack_type": "port_scanning"
                })

                print(f"🚫 IP {src_ip} scanned {unique_port_count} unique ports (offense #{activity['block_count']}), blocking for {block_duration}...")

                block_ip(src_ip, "port_scanning", {
                    "unique_ports_scanned": unique_port_count,
                    "ports": list(activity["unique_ports"]),
                    "offense_count": activity["block_count"],
                    "block_duration_seconds": int(block_duration.total_seconds())
                })

                # Schedule unblock
                unblock_time = datetime.now() + block_duration
                print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
                sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
                slow_path_queue.task_done()
                continue

            # If not blocked, send SYN-ACK
            syn_ack = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
            )
            send(syn_ack, verbose=0)
            print(f"Sent SYN-ACK to {src_ip} on port {port}")

            slow_path_queue.task_done()

        except Exception as e:
            print(f"Error in slow path processing: {e}")
            slow_path_queue.task_done()

def unblock_expired_ips():
    """Unblock IPs whose block duration has expired."""
    now = datetime.now()
    for task in list(sniff_thread.unblock_tasks):
        if now >= task["unblock_time"]:
            unblock_ip(task["ip"])
            sniff_thread.unblock_tasks.remove(task)
            # No immediate save_state() - handled by periodic saves

def periodic_state_save():
    """Save state periodically based on configured interval."""
    global last_state_save
    now = datetime.now()
    if (now - last_state_save).total_seconds() >= current_save_interval:
        save_state()
        last_state_save = now
        print(f"💾 Periodic state save completed")

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

    # Start slow path processor thread
    slow_path_thread = threading.Thread(target=process_slow_path, daemon=True)
    slow_path_thread.start()

    # Start webhook processor thread
    def webhook_processor():
        """Run webhook processing in a separate thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def webhook_loop():
            while True:
                try:
                    await process_webhook_queue()
                    await asyncio.sleep(1)  # Check every second
                except Exception as e:
                    print(f"Error in webhook processor: {e}")
                    await asyncio.sleep(5)  # Wait longer on error

        loop.run_until_complete(webhook_loop())

    if WEBHOOK_CONFIG.get("enabled", False):
        webhook_thread = threading.Thread(target=webhook_processor, daemon=True)
        webhook_thread.start()
        print("🔗 Webhook processor started")

    # Get sleep interval from config
    sleep_interval = 5  # Default
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'rb') as f:
                config = tomllib.load(f)
            sleep_interval = config.get("firewall", {}).get("sleep_interval", 5)
    except:
        pass

    print("🚀 Hybrid firewall started: Fast path for immediate decisions, slow path for complex analysis")

    # Queue startup webhook event
    queue_webhook_event("firewall_started", {
        "mode": FIREWALL_MODE,
        "unique_ports_threshold": UNIQUE_PORTS_THRESHOLD,
        "default_port_threshold": DEFAULT_PORT_THRESHOLD,
        "trusted_ips_count": len(TRUSTED_IPS),
        "webhook_enabled": WEBHOOK_CONFIG.get("enabled", False),
        "webhook_endpoints_count": len(WEBHOOK_CONFIG.get("endpoints", []))
    })

    # Monitor unblock tasks and periodic saves in the main thread
    try:
        while True:
            unblock_expired_ips()
            periodic_state_save()  # Check if it's time for periodic save
            time.sleep(sleep_interval)
    except KeyboardInterrupt:
        print("\n🛑 Stopping firewall...")
        save_state()  # Final save on shutdown