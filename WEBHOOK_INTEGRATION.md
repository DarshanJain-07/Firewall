# Firewall Webhook Integration Guide

## Overview

The firewall webhook system allows external organizations to receive real-time notifications about security events, enabling automated responses and integration with existing security infrastructure.

## Features

- **Real-time Event Delivery**: Immediate notifications for security events
- **Batch Processing**: Events are batched for efficiency
- **Secure Authentication**: HMAC-SHA256 signature verification
- **Retry Logic**: Automatic retry with exponential backoff
- **Rate Limiting**: Configurable rate limits to prevent overwhelming endpoints
- **Event Filtering**: Organizations can choose which events to receive
- **Multiple Endpoints**: Support for multiple webhook destinations

## Event Types

### 1. `firewall_started`
Sent when the firewall initializes.
```json
{
  "event_type": "firewall_started",
  "data": {
    "mode": "standard",
    "unique_ports_threshold": 7,
    "default_port_threshold": 10,
    "trusted_ips_count": 5,
    "webhook_enabled": true,
    "webhook_endpoints_count": 2
  }
}
```

### 2. `connection_attempt`
Sent for every connection attempt (high volume).
```json
{
  "event_type": "connection_attempt",
  "data": {
    "ip": "192.168.1.100",
    "port": 80,
    "src_port": 54321,
    "timestamp": "2024-01-01T12:00:00"
  }
}
```

### 3. `ip_blocked`
Sent when an IP address is blocked.
```json
{
  "event_type": "ip_blocked",
  "data": {
    "ip": "192.168.1.100",
    "reason": "port_scanning",
    "action": "blocked",
    "method": "iptables",
    "block_count": 1,
    "unique_ports_scanned": 8,
    "ports": [80, 443, 22, 8080, 3306, 5432, 8000, 9000]
  }
}
```

### 4. `ip_unblocked`
Sent when an IP address is unblocked.
```json
{
  "event_type": "ip_unblocked",
  "data": {
    "ip": "192.168.1.100",
    "reason": "timeout_expired",
    "action": "unblocked",
    "method": "iptables"
  }
}
```

### 5. `port_scanning_detected`
Sent when port scanning behavior is detected.
```json
{
  "event_type": "port_scanning_detected",
  "data": {
    "ip": "192.168.1.100",
    "unique_ports_scanned": 8,
    "threshold": 7,
    "ports": [80, 443, 22, 8080, 3306, 5432, 8000, 9000],
    "offense_count": 1,
    "block_duration_seconds": 600,
    "attack_type": "port_scanning"
  }
}
```

### 6. `distributed_attack_detected`
Sent when a distributed attack on a specific port is detected.
```json
{
  "event_type": "distributed_attack_detected",
  "data": {
    "ip": "192.168.1.100",
    "port": 80,
    "attempts": 15,
    "threshold": 2,
    "attack_type": "distributed_port_attack"
  }
}
```

### 7. `block_error` / `unblock_error`
Sent when errors occur during blocking/unblocking operations.
```json
{
  "event_type": "block_error",
  "data": {
    "ip": "192.168.1.100",
    "reason": "port_scanning",
    "error": "iptables command failed",
    "action": "block_failed"
  }
}
```

## Configuration

### Basic Configuration

Add the following to your `firewall_config.toml`:

```toml
[webhooks]
enabled = true
retry_attempts = 3
retry_delay = 5
timeout = 10
batch_size = 10
batch_timeout = 30
rate_limit = 100

[[webhooks.endpoints]]
name = "Security Operations Center"
url = "https://soc.example.com/webhooks/firewall"
secret = "your-webhook-secret-key-here"
enabled = true

[webhooks.endpoints.headers]
"X-Organization-ID" = "org-123"
"X-Environment" = "production"
```

### Advanced Configuration

```toml
# Multiple endpoints with different purposes
[[webhooks.endpoints]]
name = "Incident Response Team"
url = "https://ir.example.com/api/firewall-alerts"
secret = "ir-team-secret"
enabled = true

# Only send critical events to IR team
[webhooks.endpoints.events]
include = [
    "ip_blocked",
    "port_scanning_detected", 
    "distributed_attack_detected"
]

[[webhooks.endpoints]]
name = "Analytics Platform"
url = "https://analytics.example.com/firewall/events"
enabled = true

[webhooks.endpoints.headers]
"X-API-Key" = "analytics-api-key"
# No event filtering - receives all events
```

## Security

### Signature Verification

Each webhook request includes an HMAC-SHA256 signature in the `X-Firewall-Signature` header:

```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    if not signature.startswith('sha256='):
        return False
    
    received_signature = signature[7:]  # Remove 'sha256=' prefix
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(received_signature, expected_signature)
```

### Headers

- `X-Firewall-Signature`: HMAC-SHA256 signature (when secret is configured)
- `X-Firewall-Timestamp`: Unix timestamp of the request
- `Content-Type`: `application/json`
- `User-Agent`: `Firewall-Webhook/1.0`

## Testing

### 1. Start Test Server

```bash
python webhook_test_server.py --port 8080 --secret your-secret-key
```

### 2. Configure Firewall

Update `firewall_config.toml`:
```toml
[webhooks]
enabled = true

[[webhooks.endpoints]]
url = "http://localhost:8080"
secret = "your-secret-key"
enabled = true
```

### 3. Send Test Webhook

```bash
python webhook_client.py --test-url http://localhost:8080 --secret your-secret-key
```

## Integration Examples

### Python Flask Webhook Receiver

```python
from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)
WEBHOOK_SECRET = "your-secret-key"

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    # Verify signature
    signature = request.headers.get('X-Firewall-Signature')
    if not verify_signature(request.data.decode(), signature, WEBHOOK_SECRET):
        return jsonify({"error": "Invalid signature"}), 401
    
    # Process webhook
    webhook_data = request.json
    for event in webhook_data.get('events', []):
        process_event(event)
    
    return jsonify({"status": "success"})

def process_event(event):
    event_type = event.get('event_type')
    data = event.get('data', {})
    
    if event_type == 'ip_blocked':
        # Add to threat intelligence
        add_to_threat_db(data['ip'], data['reason'])
    elif event_type == 'port_scanning_detected':
        # Alert security team
        send_security_alert(data)
```

### Node.js Express Webhook Receiver

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.raw({type: 'application/json'}));

app.post('/webhook', (req, res) => {
    const signature = req.headers['x-firewall-signature'];
    const payload = req.body.toString();
    
    if (!verifySignature(payload, signature, process.env.WEBHOOK_SECRET)) {
        return res.status(401).json({error: 'Invalid signature'});
    }
    
    const webhookData = JSON.parse(payload);
    webhookData.events.forEach(processEvent);
    
    res.json({status: 'success'});
});

function verifySignature(payload, signature, secret) {
    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(payload)
        .digest('hex');
    
    return signature === `sha256=${expectedSignature}`;
}
```

## Best Practices

1. **Always verify signatures** when using webhook secrets
2. **Implement idempotency** using event IDs to handle duplicate deliveries
3. **Use HTTPS endpoints** for production deployments
4. **Implement proper error handling** and return appropriate HTTP status codes
5. **Monitor webhook delivery** and set up alerts for failed deliveries
6. **Filter events** to only receive relevant notifications
7. **Implement rate limiting** on your webhook endpoints
8. **Log webhook events** for debugging and audit purposes

## Troubleshooting

### Common Issues

1. **Signature verification fails**: Check that your secret matches the configuration
2. **Webhooks not delivered**: Verify endpoint URL and network connectivity
3. **High volume of events**: Use event filtering or increase batch size
4. **Timeout errors**: Increase timeout configuration or optimize endpoint response time

### Debug Mode

Enable debug logging in the firewall to see webhook delivery attempts:

```python
# Add to firewall.py for debugging
import logging
logging.basicConfig(level=logging.DEBUG)
```
