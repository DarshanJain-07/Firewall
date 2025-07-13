# Firewall Webhook System

## Overview

The firewall webhook system enables real-time integration with external security systems, allowing organizations to:

- Receive instant notifications about security events
- Automate incident response workflows
- Integrate with SIEM, SOAR, and threat intelligence platforms
- Coordinate responses across multiple security tools
- Build custom analytics and monitoring dashboards

## Quick Start

### 1. Install Dependencies

```bash
pip install aiohttp requests tomli tomli_w
```

### 2. Configure Webhooks

Run the interactive setup:

```bash
python setup_webhooks.py --interactive
```

Or manually edit `firewall_config.toml`:

```toml
[webhooks]
enabled = true

[[webhooks.endpoints]]
name = "Security Operations Center"
url = "https://soc.example.com/webhooks/firewall"
secret = "your-webhook-secret-key"
enabled = true
```

### 3. Test Integration

Start the test server:

```bash
python webhook_test_server.py --port 8080 --secret your-webhook-secret-key
```

Send a test webhook:

```bash
python webhook_client.py --test-url http://localhost:8080 --secret your-webhook-secret-key
```

### 4. Deploy Production Handler

Use the example handler as a starting point:

```bash
# Configure environment variables
export WEBHOOK_SECRET="your-secret-key"
export ALERT_EMAIL="security@example.com"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# Run the handler
python example_webhook_handler.py
```

## Files Overview

| File | Purpose |
|------|---------|
| `firewall.py` | Main firewall with webhook integration |
| `webhook_test_server.py` | Test server for receiving webhooks |
| `webhook_client.py` | Client utilities and examples |
| `example_webhook_handler.py` | Production-ready webhook handler |
| `setup_webhooks.py` | Interactive setup script |
| `WEBHOOK_INTEGRATION.md` | Detailed integration guide |

## Event Types

### Critical Events
- `ip_blocked` - IP address blocked by firewall
- `port_scanning_detected` - Port scanning behavior detected
- `distributed_attack_detected` - Coordinated attack on specific port

### Informational Events
- `firewall_started` - Firewall initialization
- `connection_attempt` - Individual connection attempts
- `ip_unblocked` - IP address unblocked

### Error Events
- `block_error` - Error during IP blocking
- `unblock_error` - Error during IP unblocking

## Security Features

### Signature Verification
All webhooks include HMAC-SHA256 signatures for authenticity verification:

```python
def verify_signature(payload, signature, secret):
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

### Rate Limiting
Configurable rate limits prevent overwhelming webhook endpoints:

```toml
[webhooks]
rate_limit = 100  # requests per minute
```

### Event Filtering
Organizations can choose which events to receive:

```toml
[[webhooks.endpoints]]
[webhooks.endpoints.events]
include = ["ip_blocked", "port_scanning_detected"]
exclude = ["connection_attempt"]
```

## Integration Examples

### SIEM Integration

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

### Threat Intelligence

```python
def handle_ip_blocked(event):
    ip = event['data']['ip']
    
    # Add to threat intel database
    threat_db.add_malicious_ip(ip, event['data']['reason'])
    
    # Share with threat intel feeds
    threat_feed.submit_indicator(ip, 'malicious')
```

### Automated Response

```python
def handle_distributed_attack(event):
    ip = event['data']['ip']
    port = event['data']['port']
    
    # Block on all firewalls
    for firewall in firewall_cluster:
        firewall.block_ip(ip)
    
    # Create incident ticket
    incident_system.create_ticket({
        'title': f'Distributed attack from {ip}',
        'severity': 'critical',
        'details': event['data']
    })
```

## Production Deployment

### Using Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY example_webhook_handler.py .
EXPOSE 5000

CMD ["python", "example_webhook_handler.py"]
```

### Using Systemd

```bash
# Create service file
python setup_webhooks.py --create-service

# Install and start
sudo cp firewall-webhook.service /etc/systemd/system/
sudo systemctl enable firewall-webhook
sudo systemctl start firewall-webhook
```

### Environment Variables

```bash
# Security
export WEBHOOK_SECRET="your-secure-secret-key"

# Database
export DATABASE_PATH="/var/lib/firewall/events.db"

# Email alerts
export SMTP_SERVER="smtp.gmail.com"
export EMAIL_USER="alerts@example.com"
export EMAIL_PASS="your-app-password"
export ALERT_EMAIL="security@example.com"

# Slack integration
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

## Monitoring and Troubleshooting

### Health Checks

```bash
# Check webhook handler health
curl http://localhost:5000/health

# Get statistics
curl http://localhost:5000/stats
```

### Logs

```bash
# View webhook handler logs
tail -f webhook_handler.log

# View firewall logs
journalctl -u firewall -f
```

### Common Issues

1. **Signature verification fails**
   - Check webhook secret matches configuration
   - Verify timestamp headers are recent

2. **High latency**
   - Increase batch size to reduce request frequency
   - Optimize webhook endpoint response time

3. **Missing events**
   - Check rate limiting configuration
   - Verify endpoint is responding with 200 status

## Best Practices

### Security
- Always use HTTPS endpoints in production
- Implement signature verification
- Use strong, unique secrets for each endpoint
- Regularly rotate webhook secrets

### Performance
- Use appropriate batch sizes (10-50 events)
- Implement proper error handling and retries
- Monitor webhook delivery success rates
- Use event filtering to reduce noise

### Reliability
- Implement idempotency using event IDs
- Store events in database for audit trail
- Set up monitoring and alerting for webhook failures
- Use multiple endpoints for redundancy

## Support

For questions or issues:

1. Check the logs for error messages
2. Verify configuration with test server
3. Review the integration guide
4. Test with webhook client utilities

## Contributing

To add new event types or improve webhook functionality:

1. Add event creation in `firewall.py`
2. Update documentation
3. Add test cases
4. Update example handlers
