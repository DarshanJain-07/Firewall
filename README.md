# Python Firewall & Intrusion Detection System

A lightweight, real-time firewall and intrusion detection system built with Python and Scapy. This script monitors network traffic, detects port scanning attempts, and automatically blocks malicious IPs using iptables.

NOTE: THIS SCRIPT WORKS ONLY ON LINUX AND UNIX BASED OPERATING SYSTEMS.

## 🔥 Current Features

### ✅ **Implemented**
- **SYN Scan Detection**: Monitors TCP SYN packets to detect port scanning attempts
- **Automatic IP Blocking**: Uses iptables to block IPs that exceed scan thresholds
- **Trusted IP Whitelist**: Hardcoded set of trusted IPs that bypass all blocking logic
- **Temporary Blocking**: Automatically unblocks IPs after a configurable duration (10 minutes default)
- **Real-time Monitoring**: Live packet inspection with immediate response
- **Scan Threshold Control**: Configurable scan count limit (currently 3 scans)
- **SYN-ACK Honeypot Response**: Responds to scans to gather more intelligence

### 🎯 **Problems Currently Solved**
1. **Port Scan Detection**: Identifies reconnaissance attempts on your system
2. **Automated Defense**: Blocks attackers without manual intervention
3. **False Positive Prevention**: Whitelists trusted IPs to avoid blocking legitimate traffic
4. **Temporary Mitigation**: Provides cooling-off period for blocked IPs
5. **Basic Threat Intelligence**: Logs scanning attempts with timestamps

## 🚀 Planned Advanced Features

### 🔍 **Enhanced Scan Detection**
- [ ] **Multiple Scan Types**: Detect SYN, FIN, NULL, XMAS, UDP, and stealth scans
- [ ] **Distributed Scan Detection**: Identify coordinated attacks from multiple IPs targeting same ports
- [ ] **Time-based Analysis**: Detect slow/low-intensity scans spread over time
- [ ] **Behavioral Analysis**: Identify abnormal traffic patterns (>300% of 30-day average)
- [ ] **Geo-location Filtering**: Block/allow traffic based on geographic origin

### 🌐 **Threat Intelligence Integration**
- [ ] **External Threat Feeds**: Integration with AbuseIPDB, VirusTotal, and other threat databases
- [ ] **Reputation Scoring**: Dynamic IP reputation based on multiple threat sources
- [ ] **IOC Matching**: Automatic blocking of known malicious indicators
- [ ] **Threat Feed Updates**: Real-time updates from security vendors

### ⚙️ **Configuration & Profiles**
- [ ] **External Config Files**: YAML/JSON configuration for thresholds, timeouts, and rules
- [ ] **Environment Profiles**: Different sensitivity levels (Normal, Aggressive, Paranoid)
- [ ] **Dynamic Thresholds**: Adaptive limits based on network baseline
- [ ] **Rule Engine**: Custom blocking rules with complex conditions

### 📊 **Monitoring & Alerting**
- [ ] **Structured Logging**: JSON-formatted logs for better parsing and analysis
- [ ] **Metrics Collection**: Prometheus/Grafana integration for dashboards
- [ ] **Real-time Alerts**: Email, Slack, webhook notifications for critical events
- [ ] **Health Monitoring**: Self-monitoring with status checks and diagnostics
- [ ] **Performance Metrics**: Latency, throughput, and resource usage tracking

### 🏗️ **Architecture & Performance**
- [ ] **Persistent State**: Maintain scan history and IP reputation across restarts
- [ ] **Async Processing**: Non-blocking packet processing with async/await
- [ ] **Queue-based Architecture**: High-throughput processing for enterprise environments
- [ ] **Graceful Degradation**: Continue monitoring even when iptables operations fail
- [ ] **Resource Optimization**: Cron-based cleanup and memory management

### 🛡️ **Advanced Security Features**
- [ ] **DDoS Protection**: Rate limiting and connection throttling
- [ ] **Protocol Analysis**: Deep packet inspection for application-layer attacks
- [ ] **Honeypot Integration**: Advanced deception techniques
- [ ] **Machine Learning**: Anomaly detection using behavioral models
- [ ] **Incident Response**: Automated response playbooks for different attack types

## 📋 Use Cases

### 🏠 **Home Networks**
- Protect personal devices from internet scanning
- Monitor suspicious activity on home routers
- Block known malicious IPs automatically

### 🏢 **Small Business**
- Protect web servers and databases from reconnaissance
- Monitor employee network activity
- Implement basic intrusion detection

### 🏭 **Enterprise (Future)**
- High-volume traffic analysis
- Integration with SIEM systems
- Compliance monitoring and reporting
- Multi-site deployment coordination

## 🚀 Quick Start

### Prerequisites
```bash
# Install required packages
sudo apt update
sudo apt install python3-pip
pip3 install scapy

# Ensure iptables is available
sudo iptables --version
```

### Basic Usage
```bash
# 1. Edit trusted IPs in firewall.py
TRUSTED_IPS = {
    "192.168.1.1",      # Your router
    "192.168.1.100",    # Your computer
    "127.0.0.1",        # Localhost
}

# 2. Run the firewall (requires root for packet capture and iptables)
sudo python3 firewall.py

# 3. Monitor the output for scan detection and blocking
```

### Configuration
```python
# Adjust these variables in firewall.py:
BLOCK_DURATION = timedelta(minutes=10)  # How long to block IPs
SCAN_THRESHOLD = 3                      # Scans before blocking
TRUSTED_IPS = {...}                     # IPs that bypass blocking
```

## 📁 Project Structure
```
├── firewall.py              # Main firewall script
├── README.md                # This documentation
└── logs/                    # Future: Log files directory
```

## 🔧 Development Roadmap

### Phase 1: Enhanced Detection (Next)
- Implement FIN, NULL, XMAS scan detection
- Add distributed scan detection
- Create basic configuration file support

### Phase 2: Intelligence Integration
- AbuseIPDB API integration
- Basic threat feed processing
- Geo-location blocking

### Phase 3: Enterprise Features
- Async processing architecture
- Metrics and monitoring
- Advanced alerting system

### Phase 4: Machine Learning
- Behavioral analysis
- Anomaly detection
- Predictive blocking

## 🤝 Contributing

This is a learning project that will evolve over time. Future contributions welcome for:
- New scan detection algorithms
- Performance optimizations
- Integration with security tools
- Documentation improvements

## ⚠️ Security Notice

- **Root Required**: Script needs root privileges for packet capture and iptables
- **Testing**: Always test in a controlled environment first
- **Backup**: Backup your iptables rules before running
- **Monitoring**: Monitor system performance and network connectivity

## 🛠️ Useful Commands

### TCPDUMP Commands
```bash
# Show packets with SYN flags
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Exclude Port 22 (SSH Traffic)
sudo tcpdump -i any tcp and not port 22 -X

# Filter traffic from specific IP
tcpdump -i any src host <specific-ip> -X
```

### IPTABLES Commands
```bash
# Add iptables rule
iptables -A INPUT -s <ip> -j DROP

# Delete iptables rule
iptables -D INPUT -s <ip> -j DROP

# List iptables rules
iptables -L -n -v

# Flush all iptables rules
iptables -F
```