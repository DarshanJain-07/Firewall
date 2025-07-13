# Advanced Firewall Replacement System

A high-performance Python-based firewall replacement with hybrid fast/slow path architecture, complete port filtering, distributed attack prevention, and enterprise-grade monitoring capabilities.

**NOTE: THIS SYSTEM WORKS ONLY ON LINUX AND UNIX BASED OPERATING SYSTEMS.**

## 🔥 Current Features

### ✅ **Firewall Replacement**
- **Complete Port Filtering**: Block all unauthorized ports, allow only configured services
- **Three Operation Modes**: Detection-only, firewall replacement, or corporate security
- **Hybrid Fast/Slow Path**: Sub-millisecond response for trusted IPs and blocked IPs
- **Memory-Optimized Performance**: All tracking in RAM with configurable persistence intervals

### ✅ **Attack Detection & Prevention**
- **Port Scan Detection**: Blocks IPs scanning multiple unique ports (threshold: 7 ports)
- **Distributed Attack Prevention**: Port-specific thresholds to counter IP rotation attacks
- **Progressive Blocking**: Escalating ban durations (10min → 2hrs → 1day → 1week)
- **Queue-Based Analysis**: Complex threat analysis doesn't block packet capture

### ✅ **Enterprise Network Support**
- **Subnet Support**: Trusted IP lists support CIDR notation for corporate networks
- **Reverse Proxy Compatible**: Handles corporate subnet systems with shared global IPs
- **Corporate Mode**: Strict port filtering with enhanced logging for compliance

### ✅ **Monitoring & Health Checks**
- **Process Monitoring**: Optimized PID-based health checks every minute
- **Functional Testing**: Daily verification that blocking actually works
- **Auto-Restart**: Automatically restarts firewall if down or malfunctioning
- **File Integrity**: SHA256 hash verification prevents script tampering

### ✅ **Security Hardening**
- **File Integrity Monitoring**: Detects unauthorized script modifications
- **Root-Only Permissions**: Critical files can only be modified by root
- **Tamper Detection**: Monitor stops immediately if files are compromised

### ✅ **High-Performance State Management**
- **Memory-Only Tracking**: All state kept in RAM for maximum performance
- **Configurable Persistence**: Mode-based save intervals (30s aggressive, 5min lenient)
- **Graceful Recovery**: Resumes exactly where it left off after restarts or failures
- **Failure Resilience**: Immediate save on errors, final save on shutdown

### ✅ **Flexible Configuration System**
- **Multiple Security Modes**: Choose from aggressive, standard, lenient, or custom modes
- **Firewall Operation Modes**: Detection-only, firewall replacement, or corporate security
- **Port Filtering Configuration**: Define exactly which ports are allowed through
- **TOML Configuration**: Human-readable config files with comments and examples
- **Environment-Specific**: Easy customization for different deployment scenarios
- **Trusted Networks**: Support for IP addresses and CIDR subnets that bypass all checks

### ✅ **Webhook Integration System**
- **Real-time Event Delivery**: Instant notifications to external security systems
- **Multiple Endpoints**: Support for SOCs, SIEM platforms, incident response teams
- **Secure Authentication**: HMAC-SHA256 signature verification for webhook security
- **Event Filtering**: Organizations choose which events to receive per endpoint
- **Batch Processing**: Efficient delivery with configurable batching and rate limiting
- **Retry Logic**: Automatic retry with exponential backoff for failed deliveries
- **Production Ready**: Complete webhook handlers with database storage and alerting

### 🔧 **Firewall Operation Modes**

#### **Detection Only Mode** (Default)
```toml
firewall_mode = "detection_only"
```
- **Purpose**: Monitor and detect attacks without blocking ports
- **Behavior**: All ports respond normally, scanning detection active
- **Use Case**: Existing firewall in place, want attack monitoring only

#### **Firewall Mode** (Complete Replacement)
```toml
firewall_mode = "firewall"
[allowed_ports]
tcp = [22, 80, 443]  # Only SSH, HTTP, HTTPS allowed
```
- **Purpose**: Full firewall replacement with port filtering
- **Behavior**: Only allowed ports respond, others dropped silently
- **Use Case**: Replace existing firewall, control exactly which services are accessible

#### **Corporate Mode** (Enterprise Security)
```toml
firewall_mode = "corporate"
[allowed_ports]
tcp = [22, 80, 443]  # Minimal required ports
```
- **Purpose**: Strict corporate security with enhanced logging
- **Behavior**: Same as firewall mode with additional compliance features
- **Use Case**: Corporate environments requiring strict port control and audit trails

### 🎯 **Problems Solved**
1. **Complete Firewall Replacement**: Drop-in replacement for traditional firewalls with port filtering
2. **High-Performance Processing**: Hybrid architecture handles high traffic without packet loss
3. **Port Scan Detection**: Identifies reconnaissance attempts across multiple ports
4. **Distributed Attacks**: Protects against IP rotation and coordinated brute force
5. **Corporate Networks**: Supports subnet whitelisting for business environments
6. **System Reliability**: Auto-monitoring and restart capabilities
7. **Script Tampering**: File integrity protection prevents unauthorized modifications
8. **Progressive Deterrence**: Escalating penalties discourage persistent attackers
9. **Service-Aware Protection**: Critical ports get stricter protection than development ports
10. **Business Continuity**: Legitimate users can access same ports repeatedly without blocks
11. **State Persistence**: Configurable persistence balancing performance vs data protection
12. **Configuration Flexibility**: Easy mode switching and customization for different environments
13. **Security Integration**: Real-time webhook notifications enable automated incident response
14. **Multi-Organization Support**: Webhook system allows multiple organizations to receive alerts
15. **SIEM/SOAR Integration**: Direct integration with security orchestration platforms

## 🚀 Quick Start

### Basic Setup (Detection Only)
```bash
# 1. Install dependencies
sudo apt update && sudo apt install python3-pip
pip3 install scapy tomli tomli-w aiohttp requests

# 2. Copy and configure
cp firewall_config.toml.example firewall_config.toml
# Edit trusted IPs in firewall_config.toml

# 3. Start firewall (detection only - monitors but allows all ports)
sudo python3 firewall.py
```

### Firewall Replacement Setup
```bash
# 1. Configure for firewall mode
nano firewall_config.toml
```
```toml
[firewall]
firewall_mode = "firewall"  # Enable port filtering

[allowed_ports]
tcp = [22, 80, 443]  # Only allow SSH, HTTP, HTTPS
```
```bash
# 2. Start firewall (blocks all unauthorized ports)
sudo python3 firewall.py
```

### Corporate Environment Setup
```bash
# 1. Configure for corporate mode
nano firewall_config.toml
```
```toml
[firewall]
mode = "aggressive"         # High security
firewall_mode = "corporate" # Strict port control

[trusted]
networks = ["192.168.0.0/16", "10.0.0.0/8"]  # Corporate subnets

[allowed_ports]
tcp = [22, 80, 443]  # Minimal required ports

[webhooks]
enabled = true

[[webhooks.endpoints]]
name = "Security Operations Center"
url = "https://soc.company.com/webhooks/firewall"
secret = "your-webhook-secret-key"
enabled = true
```
```bash
# 2. Start firewall
sudo python3 firewall.py
```

### Webhook Integration Setup
```bash
# 1. Install webhook dependencies
pip3 install -r webhook_requirements.txt

# 2. Interactive webhook configuration
python3 setup_webhooks.py --interactive

# 3. Test webhook integration
python3 webhook_test_server.py --port 8080 --secret your-secret
python3 webhook_client.py --test-url http://localhost:8080 --secret your-secret

# 4. Deploy production webhook handler
export WEBHOOK_SECRET="your-secret-key"
export ALERT_EMAIL="security@company.com"
python3 example_webhook_handler.py
```

## ⚙️ Configuration

The firewall uses a TOML configuration file for easy customization. Copy the example file and modify as needed:

```bash
cp firewall_config.toml.example firewall_config.toml
# Edit firewall_config.toml with your preferred settings
```

### Security Modes

Choose from predefined security modes or create custom settings:

#### **Aggressive Mode** - High Security
- Blocks after scanning **3 ports**
- **1-hour** activity tracking window
- **Immediate blocking** on sensitive ports (80, 443)
- Escalating penalties: `5m → 1h → 12h → 3d`

#### **Standard Mode** - Balanced (Default)
- Blocks after scanning **7 ports**
- **2-hour** activity tracking window
- **Moderate thresholds** for most ports
- Escalating penalties: `10m → 2h → 1d → 7d`

#### **Lenient Mode** - High Traffic/Development
- Blocks after scanning **15 ports**
- **24-hour** activity tracking window
- **High tolerance** for enterprise environments
- Escalating penalties: `30m → 4h → 2d → 14d`

#### **Custom Mode** - Full Control
- Define your own thresholds and settings
- Perfect for specific deployment requirements

### Configuration Examples

#### Small Office (10-50 users)
```toml
[firewall]
mode = "standard"

[trusted]
ips = ["192.168.1.1"]
networks = ["192.168.1.0/24"]
```

#### Enterprise (1000+ employees)
```toml
[firewall]
mode = "lenient"

[custom.port_thresholds]
80 = 150    # High web traffic
443 = 150   # High HTTPS traffic

[trusted]
networks = ["10.0.0.0/8", "172.16.0.0/12"]
```

#### Development Environment
```toml
[firewall]
mode = "lenient"

[custom]
unique_ports_threshold = 20
activity_window_hours = 48
```

### Trusted Networks
```python
TRUSTED_IPS = {
    "192.168.1.1",      # Individual IPs
    "127.0.0.1",
    "192.168.0.0/16",   # Corporate subnet
    "10.0.0.0/8"        # Private network
}
```

## Installation & Setup

### 1. File Permissions Setup
```bash
# Make control script executable
chmod +x firewall_control.sh

# Make security setup script executable
chmod +x secure_setup.sh
```

### 2. Security Hardening
```bash
# Run security setup (creates integrity hashes, sets permissions)
sudo ./secure_setup.sh
```

This script will:
- Create SHA256 integrity hash for `firewall.py`
- Set `firewall.py` as read-only, root-owned (`chmod 644`)
- Set `monitor_firewall.py` as executable, root-owned (`chmod 755`)
- Set `firewall.py.sha256` as read-only, root-owned (`chmod 644`)

### 3. Dependencies
```bash
# Core firewall dependencies
pip install scapy tomli tomli-w

# Webhook system dependencies (optional)
pip install aiohttp requests flask

# Or install all webhook dependencies
pip install -r webhook_requirements.txt
```

**Note**: `tomli` and `tomli-w` are for TOML state persistence. Python 3.11+ has built-in TOML reading support. Webhook dependencies are only needed if using the webhook integration system.

## Usage

### Quick Start
```bash
# Start firewall with monitoring (recommended)
sudo ./firewall_control.sh monitor

# Check status
./firewall_control.sh status
```

### Manual Control
```bash
# Start firewall only
sudo ./firewall_control.sh start

# Stop everything
sudo ./firewall_control.sh stop

# Restart firewall
sudo ./firewall_control.sh restart
```

### Direct Execution
```bash
# Run firewall directly
sudo python3 firewall.py

# Run monitor directly
sudo python3 monitor_firewall.py
```

## File Structure

```
├── firewall.py                    # Main firewall logic with webhook integration
├── monitor_firewall.py            # Health monitoring & auto-restart
├── firewall_control.sh            # Control script
├── secure_setup.sh                # Security hardening script
├── firewall_config.toml           # Configuration file (customize this)
├── firewall_config.toml.example   # Example configuration
├── firewall.py.sha256             # Integrity hash (auto-generated)
├── firewall_state.toml            # Persistent state file (auto-generated)
├── webhook_test_server.py         # Test server for webhook development
├── webhook_client.py              # Client utilities and integration examples
├── example_webhook_handler.py     # Production-ready webhook receiver
├── setup_webhooks.py              # Interactive webhook configuration
├── test_webhooks.py               # Webhook system test suite
├── webhook_requirements.txt       # Webhook system dependencies
├── WEBHOOK_INTEGRATION.md         # Detailed webhook integration guide
├── WEBHOOK_README.md              # Webhook system overview
└── README.md                      # This file
```

## Configuration System

The firewall supports flexible TOML-based configuration with multiple security modes:

### Quick Setup
1. **Copy example config**: `cp firewall_config.toml.example firewall_config.toml`
2. **Choose security mode**: Edit `mode = "standard"` to your preference
3. **Add trusted networks**: Update the `[trusted]` section with your IPs/subnets
4. **Start firewall**: The configuration is loaded automatically

### Security Mode Comparison

| Setting | Aggressive | Standard | Lenient |
|---------|------------|----------|---------|
| **Port Scan Threshold** | 3 ports | 7 ports | 15 ports |
| **Activity Window** | 1 hour | 2 hours | 24 hours |
| **Web Server (80/443)** | 1 attempt | 2 attempts | 100 attempts |
| **SSH (22)** | 2 attempts | 3 attempts | 20 attempts |
| **First Block Duration** | 5 minutes | 10 minutes | 30 minutes |

### Configuration File Structure
```toml
[firewall]
mode = "standard"  # aggressive, standard, lenient, custom
firewall_mode = "detection_only"  # detection_only, firewall, corporate

[trusted]
ips = ["127.0.0.1", "192.168.1.1"]
networks = ["192.168.0.0/16", "10.0.0.0/8"]

[allowed_ports]  # Only used when firewall_mode = "firewall" or "corporate"
tcp = [22, 80, 443]  # SSH, HTTP, HTTPS

[custom]  # Only used when mode = "custom"
unique_ports_threshold = 7
default_port_threshold = 10
activity_window_hours = 2
block_durations = ["10m", "2h", "1d", "7d"]
state_save_interval = 60  # Custom save interval

[custom.port_thresholds]
80 = 2    # Web server
443 = 2   # HTTPS
22 = 3    # SSH

[webhooks]  # Optional webhook integration
enabled = false  # Set to true to enable webhooks

[[webhooks.endpoints]]
name = "Security Team"
url = "https://security.company.com/webhooks/firewall"
secret = "your-webhook-secret"
enabled = true
```

## Persistent State Management

The firewall automatically maintains persistent state across system restarts and iptables failures:

### State Persistence Features
- **Periodic Saving**: Mode-based intervals for optimal performance vs data protection
- **Startup Recovery**: All tracking data restored when firewall starts
- **Failure Resilience**: Immediate save on iptables errors for recovery
- **Graceful Shutdown**: Final state save when firewall is stopped with Ctrl+C

### Performance-Optimized Persistence
- **Aggressive Mode**: 30-second saves (minimal data loss, high security)
- **Standard Mode**: 2-minute saves (balanced performance and protection)
- **Lenient Mode**: 5-minute saves (maximum performance, acceptable risk)
- **Custom Mode**: Configurable `state_save_interval` for specific needs

### What Gets Persisted
- **IP Activity Tracking**: Scan history, block counts, first/last seen timestamps
- **Port Access Counters**: Attack attempt counts per port across all IPs
- **Scheduled Unblock Tasks**: Pending IP unblock operations with exact timestamps
- **Progressive Block History**: Repeat offender status for escalating penalties

### State File Location
- **File**: `firewall_state.toml` (auto-generated in firewall directory)
- **Format**: TOML with ISO timestamp formatting for human readability
- **Permissions**: Readable by firewall process, automatically managed

### Recovery Scenarios
- **System Restart**: Firewall resumes with all previous tracking data intact
- **iptables Failure**: State preserved with error notification for manual recovery
- **Process Crash**: All data up to last operation is preserved and restored
- **Manual Stop/Start**: Seamless continuation of all blocking and tracking operations

## 🔗 Webhook Integration System

The firewall includes a comprehensive webhook system that enables real-time integration with external security systems, allowing organizations to receive instant notifications and automate incident response.

### Webhook Features

#### **Real-time Event Delivery**
- Instant notifications for all security events
- Configurable batching for high-volume environments
- Automatic retry with exponential backoff
- Rate limiting to prevent endpoint overwhelming

#### **Security & Authentication**
- HMAC-SHA256 signature verification
- Timestamp validation for replay attack prevention
- Custom headers for API authentication
- HTTPS endpoint support

#### **Event Types**
- `firewall_started` - System initialization
- `connection_attempt` - Individual connection attempts (high volume)
- `ip_blocked` - IP address blocked for suspicious activity
- `ip_unblocked` - IP address unblocked after timeout
- `port_scanning_detected` - Port scanning behavior detected
- `distributed_attack_detected` - Coordinated attacks on specific ports
- `block_error`/`unblock_error` - System errors during operations

#### **Multi-Organization Support**
- Multiple webhook endpoints per firewall
- Per-endpoint event filtering
- Organization-specific authentication
- Custom headers for different systems

### Quick Webhook Setup

#### 1. Interactive Configuration
```bash
python3 setup_webhooks.py --interactive
```

#### 2. Manual Configuration
```toml
[webhooks]
enabled = true
batch_size = 10
rate_limit = 100

[[webhooks.endpoints]]
name = "Security Operations Center"
url = "https://soc.company.com/webhooks/firewall"
secret = "your-webhook-secret-key"
enabled = true

[webhooks.endpoints.events]
include = ["ip_blocked", "port_scanning_detected", "distributed_attack_detected"]
```

#### 3. Test Integration
```bash
# Start test server
python3 webhook_test_server.py --port 8080 --secret your-secret

# Send test webhook
python3 webhook_client.py --test-url http://localhost:8080 --secret your-secret
```

#### 4. Production Deployment
```bash
# Configure environment
export WEBHOOK_SECRET="your-secure-secret"
export ALERT_EMAIL="security@company.com"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# Run production handler
python3 example_webhook_handler.py
```

### Integration Examples

#### SIEM Integration
```python
def handle_firewall_event(event):
    if event['event_type'] == 'ip_blocked':
        siem.send_event({
            'source': 'firewall',
            'severity': 'high',
            'ip': event['data']['ip'],
            'reason': event['data']['reason']
        })
```

#### Incident Response Automation
```python
def handle_distributed_attack(event):
    ip = event['data']['ip']
    port = event['data']['port']

    # Create incident ticket
    incident_system.create_ticket({
        'title': f'Distributed attack from {ip}',
        'severity': 'critical',
        'details': event['data']
    })

    # Block on all firewalls
    for firewall in firewall_cluster:
        firewall.block_ip(ip)
```

#### Threat Intelligence Sharing
```python
def handle_ip_blocked(event):
    ip = event['data']['ip']
    reason = event['data']['reason']

    # Add to threat intel database
    threat_db.add_malicious_ip(ip, reason)

    # Share with threat intel feeds
    threat_feed.submit_indicator(ip, 'malicious')
```

### Webhook Files

| File | Purpose |
|------|---------|
| `webhook_test_server.py` | Test server for development and testing |
| `webhook_client.py` | Client utilities and integration examples |
| `example_webhook_handler.py` | Production-ready webhook receiver |
| `setup_webhooks.py` | Interactive configuration wizard |
| `test_webhooks.py` | Comprehensive test suite |
| `WEBHOOK_INTEGRATION.md` | Detailed integration guide |
| `WEBHOOK_README.md` | Webhook system overview |

### Security Best Practices

1. **Always use HTTPS** endpoints in production
2. **Implement signature verification** for webhook authenticity
3. **Use strong, unique secrets** for each endpoint
4. **Implement proper error handling** and retries
5. **Monitor webhook delivery** success rates
6. **Filter events** to reduce noise and improve performance
7. **Implement idempotency** using event IDs

For detailed webhook integration instructions, see `WEBHOOK_INTEGRATION.md`.

## 🔍 Attacker's View (Nmap Results)

### Detection Only Mode
```bash
# All ports appear open (monitoring only)
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https
3306/tcp open     unknown
8080/tcp open     unknown
```

### Firewall Mode (Only 22, 80, 443 allowed)
```bash
# Only allowed ports respond, others filtered
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https
3306/tcp filtered unknown  # Dropped by firewall
8080/tcp filtered unknown  # Dropped by firewall
```

### Corporate Mode
```bash
# Same as firewall mode with enhanced logging
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https
# All other ports: filtered (silently dropped)
```

**Key Security Benefit**: In firewall/corporate modes, attackers cannot determine which services might be running on blocked ports, significantly reducing reconnaissance value.

## High-Performance Design

### Real-World Performance Optimizations
The firewall is optimized for typical network scenarios:
- **Office Employees**: Instant access via fast path (trusted IP bypass)
- **Single Attackers**: Efficient detection via slow path queue processing
- **High Traffic**: Memory-only tracking with configurable persistence intervals

### Performance Characteristics
- **Fast Path Latency**: < 1ms for trusted IPs (immediate SYN-ACK)
- **Blocked IP Response**: < 1ms (memory cache lookup, packet drop)
- **Complex Analysis**: Queued processing, no blocking of packet capture
- **Memory Usage**: Minimal overhead, all tracking data in RAM

### Scalability Features
- **Queue-based Processing**: Handles traffic bursts without packet loss
- **Configurable Intervals**: Balance performance vs data protection
- **Thread Separation**: Packet capture independent of analysis processing
- **Cache Optimization**: Blocked IP cache eliminates repeated iptables calls

### Mode-Specific Performance
```
Aggressive Mode: Security-first (30s saves, immediate blocking)
Standard Mode:   Balanced (2min saves, good performance)
Lenient Mode:    Performance-first (5min saves, high throughput)
Custom Mode:     Fully configurable for specific requirements
```

## Security Features

### File Integrity Protection
- **SHA256 Verification**: Monitor checks file integrity every minute
- **Tamper Detection**: Stops immediately if `firewall.py` is modified
- **Root Ownership**: Only root can modify critical files

### Permission Structure
```bash
# After running secure_setup.sh:
-rw-r--r-- root:root firewall.py           # Read-only, root owned
-rwxr-xr-x root:root monitor_firewall.py   # Executable, root owned
-rw-r--r-- root:root firewall.py.sha256    # Read-only, root owned
-rwxr-xr-x user:user firewall_control.sh   # User executable
```

## Monitoring Details

### Process Monitoring (Every Minute)
- **Optimized PID Check**: Uses stored PID + `os.kill(pid, 0)` for fast verification
- **Fallback**: Auto-falls back to `pgrep` if permission issues
- **Auto-Restart**: Immediately restarts if process is down

### Functional Testing (Daily)
- **Real Attack Simulation**: Sends packets from fake IP to 8 ports
- **Blocking Verification**: Checks if test IP gets blocked in iptables
- **Clean Cleanup**: Removes test IP after verification
- **Safety**: Only runs once per day to avoid self-blocking

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Ensure running as root for iptables access
sudo python3 monitor_firewall.py
```

**Integrity Check Failed**
```bash
# Recreate integrity hash if legitimate changes made
sudo python3 -c "
import hashlib
with open('firewall.py', 'rb') as f:
    hash_val = hashlib.sha256(f.read()).hexdigest()
with open('firewall.py.sha256', 'w') as f:
    f.write(hash_val)
"
```

**Monitor Not Starting**
```bash
# Check if dependencies are installed
pip install scapy tomli tomli-w

# Verify file permissions
ls -la firewall.py monitor_firewall.py
```

**State File Issues**
```bash
# Check if state file exists and is readable
ls -la firewall_state.toml

# Reset state file if corrupted
rm firewall_state.toml
# Firewall will create new state file on next startup

# View current state file contents (human-readable TOML)
cat firewall_state.toml
```

## Advanced Configuration

### Custom Thresholds
Edit `firewall.py` (requires root):
```python
UNIQUE_PORTS_THRESHOLD = 7  # Ports before blocking
ACTIVITY_WINDOW = timedelta(hours=2)  # Tracking window
```

### Custom Block Durations
```python
BLOCK_DURATIONS = [
    timedelta(minutes=10),  # First offense
    timedelta(hours=2),     # Second offense
    timedelta(days=1),      # Third offense
    timedelta(days=7)       # Fourth+ offense
]
```

### Adding Trusted Networks
```python
TRUSTED_IPS = {
    "your.trusted.ip",
    "192.168.0.0/24",      # Your subnet
    "10.0.0.0/8"           # Corporate network
}
```

## Architecture

### Hybrid Fast/Slow Path Performance Architecture
The firewall uses a dual-path approach optimized for high traffic environments:

#### **Fast Path** (Immediate Decisions)
1. **Trusted IP Check**: Instant allow with immediate SYN-ACK response (with port filtering)
2. **Blocked IP Cache**: Memory-based lookup, instant drop for known blocked IPs
3. **Port Filtering**: Drop unauthorized ports silently (firewall/corporate modes)
4. **Zero I/O Operations**: No file or subprocess calls in fast path

#### **Slow Path** (Complex Analysis)
1. **Queue-based Processing**: Suspicious packets queued for detailed analysis
2. **Port Scanning Detection**: Tracks unique ports accessed per IP over time
3. **Distributed Attack Detection**: Monitors access attempts per port across all IPs
4. **Progressive Blocking**: Escalating ban durations for repeat offenders

### Attack Detection Logic
1. **Unique Port Scanning**: Tracks ports accessed per IP over time window
2. **Distributed Attacks**: Monitors access attempts per port across all IPs
3. **Progressive Blocking**: Increases ban duration for repeat offenders
4. **Trusted Bypass**: Skips all checks for trusted IPs/subnets

### Performance Optimizations
1. **Memory-Only Tracking**: All state kept in memory for maximum speed
2. **Periodic State Saves**: Configurable intervals based on security mode
   - **Aggressive**: 30 seconds (minimal data loss)
   - **Standard**: 2 minutes (balanced)
   - **Lenient**: 5 minutes (maximum performance)
3. **Blocked IP Caching**: Eliminates repeated iptables lookups
4. **Queue-based Processing**: Prevents packet capture blocking on analysis

### Monitoring Architecture
1. **Primary Check**: Fast PID verification every minute
2. **Secondary Check**: Functional blocking test once daily
3. **Auto-Recovery**: Restarts firewall if either check fails
4. **Security Validation**: Integrity check prevents tampering

### State Persistence Architecture
1. **Periodic Saving**: Mode-based intervals for optimal performance
2. **Startup Recovery**: State loaded before packet processing begins
3. **Error Handling**: Immediate save on iptables failures for recovery
4. **Graceful Shutdown**: Final state save on SIGINT (Ctrl+C) termination

## Complete Setup Checklist

### Initial Setup
```bash
# 1. Install dependencies
pip install scapy tomli tomli-w

# 2. Install webhook dependencies (optional)
pip install -r webhook_requirements.txt

# 3. Create configuration file
cp firewall_config.toml.example firewall_config.toml
# Edit firewall_config.toml with your settings

# 4. Configure webhooks (optional)
python3 setup_webhooks.py --interactive

# 5. Make scripts executable
chmod +x firewall_control.sh
chmod +x secure_setup.sh

# 6. Run security hardening
sudo ./secure_setup.sh
```

### File Permissions After Setup
```bash
# Verify permissions are correct:
ls -la firewall.py          # Should be: -rw-r--r-- root:root
ls -la monitor_firewall.py  # Should be: -rwxr-xr-x root:root
ls -la firewall.py.sha256   # Should be: -rw-r--r-- root:root
ls -la firewall_control.sh  # Should be: -rwxr-xr-x user:user
```

### Running the System
```bash
# Start with monitoring (recommended)
sudo ./firewall_control.sh monitor

# Or start components separately
sudo ./firewall_control.sh start
sudo python3 monitor_firewall.py

# Test webhook integration (if configured)
python3 test_webhooks.py
```

### Webhook Testing
```bash
# Test webhook configuration
python3 setup_webhooks.py --test-url https://your-webhook-endpoint.com

# Run webhook test server
python3 webhook_test_server.py --port 8080 --secret your-secret

# Send test webhook
python3 webhook_client.py --test-url http://localhost:8080 --secret your-secret

# Run comprehensive webhook tests
python3 test_webhooks.py
```

## License

This project is for educational and security research purposes.