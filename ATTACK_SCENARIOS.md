# Attack Scenarios and Firewall Response

This document demonstrates how the enhanced firewall responds to various real-world attack scenarios.

## Scenario 1: Basic Port Scanner

**Attack**: Attacker runs `nmap -sS target` (SYN scan)

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 22 (flags: S)
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 23 (flags: S)
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 25 (flags: S)
... (continues for 7+ ports)
🚫 IP 192.168.1.100 scanned 8 unique ports (offense #1), blocking for 0:10:00...
```

**Result**: IP blocked after scanning 7+ unique ports, 10-minute block duration.

---

## Scenario 2: Stealth Scanner

**Attack**: Attacker runs `nmap -sF target` (FIN scan to avoid detection)

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 80 (flags: F)
Detected FIN_SCAN from 192.168.1.100 on port 80 - not responding (stealth mode)
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 443 (flags: F)
Detected FIN_SCAN from 192.168.1.100 on port 443 - not responding (stealth mode)
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 22 (flags: F)
Detected FIN_SCAN from 192.168.1.100 on port 22 - not responding (stealth mode)
🚫 IP 192.168.1.100 using suspicious scans (3 FIN_SCAN attempts), blocking for 0:10:00...
```

**Result**: IP blocked after just 3 suspicious scans, firewall operates in stealth mode.

---

## Scenario 3: Advanced Evasion Attempt

**Attack**: Attacker uses multiple scan types to evade detection

```bash
nmap -sN target    # NULL scan
nmap -sX target    # XMAS scan  
nmap -sA target    # ACK scan
```

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using NULL_SCAN on port 80 (flags: )
Detected NULL_SCAN from 192.168.1.100 on port 80 - not responding (stealth mode)
🔍 Analyzing 192.168.1.100 using XMAS_SCAN on port 80 (flags: FPU)
Detected XMAS_SCAN from 192.168.1.100 on port 80 - not responding (stealth mode)
🔍 Analyzing 192.168.1.100 using ACK_SCAN on port 80 (flags: A)
Detected ACK_SCAN from 192.168.1.100 on port 80 - not responding (stealth mode)
🚫 IP 192.168.1.100 using suspicious scans (3 ACK_SCAN attempts), blocking for 0:10:00...
```

**Result**: All stealth techniques detected, IP blocked quickly.

---

## Scenario 4: Distributed Attack

**Attack**: Multiple IPs target the same sensitive port (e.g., SSH on port 22)

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 22 (flags: S)
🔍 Analyzing 192.168.1.101 using SYN_SCAN on port 22 (flags: S)
🔍 Analyzing 192.168.1.102 using SYN_SCAN on port 22 (flags: S)
🔍 Analyzing 192.168.1.103 using SYN_SCAN on port 22 (flags: S)
🚫 Port 22 under distributed attack (4 > 3 attempts), blocking IP 192.168.1.103...
```

**Result**: Port-specific threshold triggered, latest IP blocked.

---

## Scenario 5: Repeat Offender

**Attack**: Previously blocked IP returns and scans again

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 80 (flags: F)
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 443 (flags: F)
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 22 (flags: F)
🚫 IP 192.168.1.100 using suspicious scans (3 FIN_SCAN attempts), blocking for 2:00:00...
```

**Result**: Progressive blocking - second offense gets 2-hour block instead of 10 minutes.

---

## Scenario 6: Trusted IP Scanning

**Attack**: Trusted IP (e.g., security scanner) performs scans

**Firewall Response**:
```
⚠️ Trusted IP 192.168.1.1 using FIN_SCAN on port 80 - allowing but logging
⚠️ Trusted IP 192.168.1.1 using XMAS_SCAN on port 443 - allowing but logging
✅ Trusted IP 192.168.1.1 accessing port 22 - allowing
```

**Result**: Trusted IPs are allowed but suspicious activity is still logged.

---

## Scenario 7: Slow Scan Attack

**Attack**: Attacker uses slow scanning to avoid detection

```bash
nmap -T0 target  # Very slow scan with 5-minute delays
```

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 22 (flags: S)
... (5 minutes later)
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 23 (flags: S)
... (continues slowly)
🚫 IP 192.168.1.100 scanned 8 unique ports (offense #1), blocking for 0:10:00...
```

**Result**: Even slow scans are detected due to 2-hour activity window.

---

## Scenario 8: Mixed Attack Pattern

**Attack**: Sophisticated attacker mixes normal and suspicious traffic

**Firewall Response**:
```
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 80 (flags: S)
Sent SYN-ACK to 192.168.1.100 on port 80
🔍 Analyzing 192.168.1.100 using FIN_SCAN on port 22 (flags: F)
Detected FIN_SCAN from 192.168.1.100 on port 22 - not responding (stealth mode)
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 443 (flags: S)
Sent SYN-ACK to 192.168.1.100 on port 443
🔍 Analyzing 192.168.1.100 using NULL_SCAN on port 25 (flags: )
Detected NULL_SCAN from 192.168.1.100 on port 25 - not responding (stealth mode)
🔍 Analyzing 192.168.1.100 using XMAS_SCAN on port 53 (flags: FPU)
Detected XMAS_SCAN from 192.168.1.100 on port 53 - not responding (stealth mode)
🚫 IP 192.168.1.100 using suspicious scans (3 XMAS_SCAN attempts), blocking for 0:10:00...
```

**Result**: Normal traffic allowed, suspicious patterns detected and blocked.

---

## Scenario 9: Corporate Environment

**Attack**: External scan against corporate firewall with allowed ports

**Configuration**:
```toml
[firewall]
firewall_mode = "corporate"

[allowed_ports]
tcp = [80, 443, 22]
```

**Firewall Response**:
```
🚫 Port 8080 not allowed, dropping SYN_SCAN from 192.168.1.100
🚫 Port 3306 not allowed, dropping FIN_SCAN from 192.168.1.100
🔍 Analyzing 192.168.1.100 using SYN_SCAN on port 80 (flags: S)
Sent SYN-ACK to 192.168.1.100 on port 80
```

**Result**: Only allowed ports respond, others are silently dropped.

---

## Scenario 10: Webhook Integration

**Attack**: Any scan triggers webhook notifications

**Webhook Payload**:
```json
{
  "events": [
    {
      "id": "abc123",
      "timestamp": "2024-01-15T10:30:00",
      "event_type": "suspicious_scanning_detected",
      "data": {
        "ip": "192.168.1.100",
        "scan_type": "FIN_SCAN",
        "total_suspicious_scans": 3,
        "threshold": 3,
        "scan_types_used": {
          "FIN_SCAN": 3
        },
        "offense_count": 1,
        "block_duration_seconds": 600,
        "attack_type": "suspicious_scanning"
      }
    }
  ]
}
```

**Result**: Real-time alerts sent to security team for immediate response.

---

## Key Advantages

1. **Multi-Vector Detection**: Catches both obvious and stealth attacks
2. **Adaptive Response**: Different responses for different threat levels
3. **Stealth Operation**: Doesn't reveal firewall presence to attackers
4. **Progressive Penalties**: Escalating consequences for repeat offenders
5. **Comprehensive Logging**: Full audit trail for forensic analysis
6. **Real-time Alerts**: Immediate notification of security events

This enhanced firewall provides enterprise-grade protection against sophisticated scanning and reconnaissance attacks.
