# TCP Scan Detection Documentation

## Overview

The firewall now detects multiple types of TCP scans beyond just SYN scans. This document explains the different scan types, their characteristics, and how the firewall responds to them.

## Supported Scan Types

### 1. SYN Scan (Normal)
- **TCP Flags**: `S` (SYN)
- **Description**: Normal connection attempt or standard port scan
- **Suspicion Level**: Low (not inherently suspicious)
- **Response**: Sends SYN-ACK if port is open and IP is not blocked

### 2. FIN Scan (Stealth)
- **TCP Flags**: `F` (FIN)
- **Description**: Stealth scan technique that sends FIN packets
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

### 3. NULL Scan (Stealth)
- **TCP Flags**: None (empty)
- **Description**: Highly suspicious scan with no flags set
- **Suspicion Level**: Very High
- **Response**: No response (stealth mode), logs and tracks

### 4. XMAS Scan (Stealth)
- **TCP Flags**: `FPU` (FIN, PSH, URG)
- **Description**: "Christmas tree" scan with multiple flags set
- **Suspicion Level**: Very High
- **Response**: No response (stealth mode), logs and tracks

### 5. ACK Scan (Firewall Detection)
- **TCP Flags**: `A` (ACK)
- **Description**: Used to detect firewall rules and stateful inspection
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

### 6. Maimon Scan (Stealth)
- **TCP Flags**: `FA` (FIN, ACK)
- **Description**: Named after Uriel Maimon, exploits BSD TCP stack behavior
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

### 7. RST Scan
- **TCP Flags**: `R` (RST)
- **Description**: Reset packet scan
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

### 8. PSH Scan
- **TCP Flags**: `P` (PSH)
- **Description**: Push-only scan
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

### 9. URG Scan
- **TCP Flags**: `U` (URG)
- **Description**: Urgent-only scan
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

### 10. Custom/Unknown Scans
- **TCP Flags**: Various unusual combinations
- **Description**: Custom or unknown flag combinations
- **Suspicion Level**: High
- **Response**: No response (stealth mode), logs and tracks

## Detection Thresholds

### Suspicious Scan Threshold
- **Default**: 3 suspicious scans from the same IP
- **Action**: Progressive blocking with escalating durations
- **Configurable**: Can be adjusted in firewall configuration

### Port Scanning Threshold
- **Default**: 7 unique ports scanned from the same IP
- **Action**: Progressive blocking with escalating durations
- **Configurable**: Can be adjusted via `unique_ports_threshold`

## Blocking Behavior

### Progressive Blocking
1. **First Offense**: 10 minutes
2. **Second Offense**: 2 hours
3. **Third Offense**: 1 day
4. **Fourth+ Offense**: 1 week

### Immediate Blocking Triggers
1. **Suspicious Scanning**: 3+ non-SYN scans from same IP
2. **Port Scanning**: 7+ unique ports scanned from same IP
3. **Distributed Attack**: Exceeding port-specific thresholds

## Stealth Mode

For all suspicious scan types (non-SYN), the firewall operates in stealth mode:
- No responses are sent back to the scanner
- All activity is logged and tracked
- Webhook events are generated for monitoring
- Scan types are recorded for analysis

## Analytics and Reporting

### Scan Statistics
- Total IPs tracked
- Scan type summary (counts per type)
- Most suspicious IPs
- Top active scanners
- Scan patterns analysis

### Periodic Reports
- Generated every 5 minutes by default
- Displayed on console and available via webhooks
- Includes top suspicious IPs and scan type breakdown

## Testing

Use the provided test script to verify scan detection:

```bash
# Test all scan types
sudo python3 test_scan_detection.py 127.0.0.1

# Test specific scan type
sudo python3 test_scan_detection.py 127.0.0.1 --scan-type fin

# Test with custom port and delay
sudo python3 test_scan_detection.py 127.0.0.1 --port 8080 --delay 2.0
```

## Configuration

Scan detection behavior can be configured via `firewall_config.toml`:

```toml
[modes.standard]
unique_ports_threshold = 7  # Port scanning threshold
activity_window_hours = 2   # Time window for tracking

[firewall]
mode = "standard"
sleep_interval = 5  # Main loop interval
```

## Webhook Events

The following webhook events are generated for scan detection:

- `connection_attempt`: Every scan attempt with scan type info
- `suspicious_scanning_detected`: When suspicious scan threshold is reached
- `port_scanning_detected`: When port scanning threshold is reached
- `distributed_attack_detected`: When port-specific thresholds are exceeded

## Log Messages

Look for these log patterns to monitor scan detection:

- `🔍 Analyzing <IP> using <SCAN_TYPE> on port <PORT>`
- `🚫 IP <IP> using suspicious scans`
- `Detected <SCAN_TYPE> from <IP> on port <PORT> - not responding (stealth mode)`

## Security Benefits

1. **Enhanced Detection**: Catches stealth scans that bypass traditional detection
2. **Stealth Response**: Doesn't reveal firewall presence to attackers
3. **Progressive Blocking**: Escalating penalties for repeat offenders
4. **Comprehensive Logging**: Detailed tracking for forensic analysis
5. **Real-time Analytics**: Immediate visibility into attack patterns
