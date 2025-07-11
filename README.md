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

### 🎯 **Problems Solved**
1. **Port Scan Detection**: Identifies reconnaissance attempts across multiple ports
2. **Distributed Attacks**: Protects against IP rotation and coordinated brute force
3. **Corporate Networks**: Supports subnet whitelisting for business environments
4. **System Reliability**: Auto-monitoring and restart capabilities
5. **Script Tampering**: File integrity protection prevents unauthorized modifications
6. **Progressive Deterrence**: Escalating penalties discourage persistent attackers
7. **Service-Aware Protection**: Critical ports get stricter protection than development ports
8. **Business Continuity**: Legitimate users can access same ports repeatedly without blocks

## ⚙️ Configuration

### Port-Specific Thresholds
```python
PORT_THRESHOLDS = {
    80: 2,      # Web server - stricter
    443: 2,     # HTTPS - stricter
    22: 3,      # SSH - moderate
    8000: 10,   # Development server - lenient
    8080: 10,   # Alternative HTTP - lenient
    3306: 5,    # MySQL - moderate
    5432: 5,    # PostgreSQL - moderate
}
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
pip install scapy
```

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
├── firewall.py.sha256       # Integrity hash (auto-generated)
└── README.md               # This file
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
# Check if scapy is installed
pip install scapy

# Verify file permissions
ls -la firewall.py monitor_firewall.py
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

## Complete Setup Checklist

### Initial Setup
```bash
# 1. Install dependencies
pip install scapy

# 2. Make scripts executable
chmod +x firewall_control.sh
chmod +x secure_setup.sh

# 3. Run security hardening
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