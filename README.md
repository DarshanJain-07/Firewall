# Advanced Firewall System

A comprehensive Python-based firewall with distributed attack prevention, subnet support, monitoring, and security hardening features.

**NOTE: THIS SYSTEM WORKS ONLY ON LINUX AND UNIX BASED OPERATING SYSTEMS.**

## 🔥 Current Features

### ✅ **Core Protection**
- **Port Scan Detection**: Blocks IPs scanning multiple unique ports (threshold: 7 ports)
- **Distributed Attack Prevention**: Port-specific thresholds to counter IP rotation attacks
- **Progressive Blocking**: Escalating ban durations (10min → 2hrs → 1day → 1week)
- **Subnet Support**: Trusted IP lists support CIDR notation for corporate networks
- **Reverse Proxy Compatible**: Handles corporate subnet systems with shared global IPs

### ✅ **Monitoring & Health Checks**
- **Process Monitoring**: Optimized PID-based health checks every minute
- **Functional Testing**: Daily verification that blocking actually works
- **Auto-Restart**: Automatically restarts firewall if down or malfunctioning
- **File Integrity**: SHA256 hash verification prevents script tampering

### ✅ **Security Hardening**
- **File Integrity Monitoring**: Detects unauthorized script modifications
- **Root-Only Permissions**: Critical files can only be modified by root
- **Tamper Detection**: Monitor stops immediately if files are compromised

### ✅ **Persistent State Management**
- **Automatic State Saving**: All tracking data saved after every iptables operation
- **Graceful Recovery**: Resumes exactly where it left off after restarts or failures
- **Failure Resilience**: State preserved even when iptables commands fail
- **Zero Data Loss**: IP activity, port counters, and scheduled unblocks persist across reboots

### ✅ **Flexible Configuration System**
- **Multiple Security Modes**: Choose from aggressive, standard, lenient, or custom modes
- **TOML Configuration**: Human-readable config files with comments and examples
- **Environment-Specific**: Easy customization for different deployment scenarios
- **Trusted Networks**: Support for IP addresses and CIDR subnets that bypass all checks

### 🎯 **Problems Solved**
1. **Port Scan Detection**: Identifies reconnaissance attempts across multiple ports
2. **Distributed Attacks**: Protects against IP rotation and coordinated brute force
3. **Corporate Networks**: Supports subnet whitelisting for business environments
4. **System Reliability**: Auto-monitoring and restart capabilities
5. **Script Tampering**: File integrity protection prevents unauthorized modifications
6. **Progressive Deterrence**: Escalating penalties discourage persistent attackers
7. **Service-Aware Protection**: Critical ports get stricter protection than development ports
8. **Business Continuity**: Legitimate users can access same ports repeatedly without blocks
9. **State Persistence**: No data loss during system restarts, iptables failures, or crashes
10. **Configuration Flexibility**: Easy mode switching and customization for different environments

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
pip install scapy tomli tomli-w
```

**Note**: `tomli` and `tomli-w` are for TOML state persistence. Python 3.11+ has built-in TOML reading support.

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
├── firewall.py              # Main firewall logic
├── monitor_firewall.py      # Health monitoring & auto-restart
├── firewall_control.sh      # Control script
├── secure_setup.sh          # Security hardening script
├── firewall_config.toml     # Configuration file (customize this)
├── firewall_config.toml.example  # Example configuration
├── firewall.py.sha256       # Integrity hash (auto-generated)
├── firewall_state.toml      # Persistent state file (auto-generated)
└── README.md               # This file
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

[trusted]
ips = ["127.0.0.1", "192.168.1.1"]
networks = ["192.168.0.0/16", "10.0.0.0/8"]

[custom]  # Only used when mode = "custom"
unique_ports_threshold = 7
default_port_threshold = 10
activity_window_hours = 2
block_durations = ["10m", "2h", "1d", "7d"]

[custom.port_thresholds]
80 = 2    # Web server
443 = 2   # HTTPS
22 = 3    # SSH
```

## Persistent State Management

The firewall automatically maintains persistent state across system restarts and iptables failures:

### State Persistence Features
- **Automatic Saving**: State saved after every iptables operation (block/unblock)
- **Startup Recovery**: All tracking data restored when firewall starts
- **Failure Resilience**: State preserved even when iptables commands fail
- **Graceful Shutdown**: State saved when firewall is stopped with Ctrl+C

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

### Attack Detection Logic
1. **Unique Port Scanning**: Tracks ports accessed per IP over time window
2. **Distributed Attacks**: Monitors access attempts per port across all IPs
3. **Progressive Blocking**: Increases ban duration for repeat offenders
4. **Trusted Bypass**: Skips all checks for trusted IPs/subnets

### Monitoring Architecture
1. **Primary Check**: Fast PID verification every minute
2. **Secondary Check**: Functional blocking test once daily
3. **Auto-Recovery**: Restarts firewall if either check fails
4. **Security Validation**: Integrity check prevents tampering

### State Persistence Architecture
1. **Automatic Saving**: State saved after every iptables operation
2. **Startup Recovery**: State loaded before packet processing begins
3. **Failure Handling**: State preserved even during iptables command failures
4. **Graceful Shutdown**: State saved on SIGINT (Ctrl+C) termination

## Complete Setup Checklist

### Initial Setup
```bash
# 1. Install dependencies
pip install scapy tomli tomli-w

# 2. Create configuration file
cp firewall_config.toml.example firewall_config.toml
# Edit firewall_config.toml with your settings

# 3. Make scripts executable
chmod +x firewall_control.sh
chmod +x secure_setup.sh

# 4. Run security hardening
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
```

## License

This project is for educational and security research purposes.