#!/usr/bin/env python3
"""
Webhook Client for Firewall Integration
Utilities for organizations to integrate with firewall webhooks.
"""

import json
import hmac
import hashlib
import time
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
import argparse

class FirewallWebhookClient:
    """Client for handling firewall webhook events."""
    
    def __init__(self, webhook_secret: Optional[str] = None):
        self.webhook_secret = webhook_secret
        self.event_handlers = {}
        
    def verify_signature(self, payload: str, signature: str) -> bool:
        """Verify webhook signature."""
        if not self.webhook_secret:
            return True  # No verification if no secret
            
        if not signature.startswith('sha256='):
            return False
            
        received_signature = signature[7:]  # Remove 'sha256=' prefix
        expected_signature = hmac.new(
            self.webhook_secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(received_signature, expected_signature)
    
    def register_handler(self, event_type: str, handler_func):
        """Register a handler function for a specific event type."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler_func)
    
    def process_webhook(self, payload: str, signature: Optional[str] = None) -> Dict[str, Any]:
        """Process incoming webhook payload."""
        # Verify signature
        if signature and not self.verify_signature(payload, signature):
            return {"status": "error", "message": "Invalid signature"}
        
        try:
            webhook_data = json.loads(payload)
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"Invalid JSON: {e}"}
        
        # Process events
        events = webhook_data.get('events', [])
        processed_events = []
        
        for event in events:
            event_type = event.get('event_type')
            result = self.handle_event(event)
            processed_events.append({
                "event_id": event.get('id'),
                "event_type": event_type,
                "status": result.get("status", "processed"),
                "message": result.get("message", "")
            })
        
        return {
            "status": "success",
            "processed_events": len(processed_events),
            "events": processed_events
        }
    
    def handle_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a single event."""
        event_type = event.get('event_type')
        
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    result = handler(event)
                    if result:
                        return result
                except Exception as e:
                    return {"status": "error", "message": f"Handler error: {e}"}
        
        return {"status": "processed", "message": "No specific handler"}

# Example event handlers
def handle_ip_blocked(event: Dict[str, Any]) -> Dict[str, Any]:
    """Example handler for IP blocked events."""
    data = event.get('data', {})
    ip = data.get('ip')
    reason = data.get('reason')
    
    print(f"🚫 IP Blocked Alert: {ip} blocked for {reason}")
    
    # Example: Add to threat intelligence database
    # threat_db.add_malicious_ip(ip, reason)
    
    # Example: Send to SIEM
    # siem.send_alert("ip_blocked", data)
    
    # Example: Update firewall rules on other systems
    # for firewall in other_firewalls:
    #     firewall.block_ip(ip)
    
    return {"status": "processed", "message": f"IP {ip} processed"}

def handle_port_scanning(event: Dict[str, Any]) -> Dict[str, Any]:
    """Example handler for port scanning events."""
    data = event.get('data', {})
    ip = data.get('ip')
    ports_scanned = data.get('unique_ports_scanned', 0)
    
    print(f"🔍 Port Scanning Alert: {ip} scanned {ports_scanned} ports")
    
    # Example: Escalate to security team
    # security_team.send_alert("port_scanning", {
    #     "ip": ip,
    #     "severity": "high" if ports_scanned > 10 else "medium",
    #     "ports": data.get('ports', [])
    # })
    
    return {"status": "processed", "message": f"Port scanning from {ip} processed"}

def handle_distributed_attack(event: Dict[str, Any]) -> Dict[str, Any]:
    """Example handler for distributed attack events."""
    data = event.get('data', {})
    ip = data.get('ip')
    port = data.get('port')
    attempts = data.get('attempts', 0)
    
    print(f"⚡ Distributed Attack Alert: {ip} attacking port {port} ({attempts} attempts)")
    
    # Example: Coordinate response across multiple systems
    # incident_response.create_incident({
    #     "type": "distributed_attack",
    #     "source_ip": ip,
    #     "target_port": port,
    #     "severity": "critical"
    # })
    
    return {"status": "processed", "message": f"Distributed attack from {ip} processed"}

def handle_firewall_started(event: Dict[str, Any]) -> Dict[str, Any]:
    """Example handler for firewall startup events."""
    data = event.get('data', {})
    mode = data.get('mode')
    
    print(f"🚀 Firewall Started: Mode {mode}")
    
    # Example: Update monitoring dashboard
    # dashboard.update_firewall_status("online", mode)
    
    return {"status": "processed", "message": "Firewall startup processed"}

def send_test_webhook(url: str, secret: Optional[str] = None):
    """Send a test webhook to verify integration."""
    test_event = {
        "events": [{
            "id": "test-event-123",
            "timestamp": datetime.now().isoformat(),
            "event_type": "test_event",
            "version": "1.0",
            "source": "firewall",
            "data": {
                "message": "This is a test webhook event",
                "test_timestamp": datetime.now().isoformat()
            }
        }],
        "batch_size": 1,
        "timestamp": datetime.now().isoformat()
    }
    
    payload = json.dumps(test_event, sort_keys=True)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Firewall-Webhook-Test/1.0"
    }
    
    # Add signature if secret provided
    if secret:
        signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        headers["X-Firewall-Signature"] = f"sha256={signature}"
    
    headers["X-Firewall-Timestamp"] = str(int(time.time()))
    
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        print(f"✅ Test webhook sent to {url}")
        print(f"📊 Response: {response.status_code} - {response.text}")
        return True
    except Exception as e:
        print(f"❌ Failed to send test webhook: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Firewall Webhook Client')
    parser.add_argument('--test-url', help='Send test webhook to this URL')
    parser.add_argument('--secret', help='Webhook secret for signature')
    parser.add_argument('--demo', action='store_true', help='Run demo with example handlers')
    
    args = parser.parse_args()
    
    if args.test_url:
        print(f"🧪 Sending test webhook to {args.test_url}")
        send_test_webhook(args.test_url, args.secret)
        return
    
    if args.demo:
        print("🎯 Firewall Webhook Client Demo")
        print("="*50)
        
        # Create client
        client = FirewallWebhookClient(args.secret)
        
        # Register example handlers
        client.register_handler('ip_blocked', handle_ip_blocked)
        client.register_handler('port_scanning_detected', handle_port_scanning)
        client.register_handler('distributed_attack_detected', handle_distributed_attack)
        client.register_handler('firewall_started', handle_firewall_started)
        
        # Example webhook payload
        example_payload = json.dumps({
            "events": [
                {
                    "id": "demo-event-1",
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "ip_blocked",
                    "version": "1.0",
                    "source": "firewall",
                    "data": {
                        "ip": "192.168.1.100",
                        "reason": "port_scanning",
                        "action": "blocked",
                        "block_count": 1
                    }
                }
            ],
            "batch_size": 1,
            "timestamp": datetime.now().isoformat()
        })
        
        print("📦 Processing example webhook payload...")
        result = client.process_webhook(example_payload)
        print(f"📊 Result: {json.dumps(result, indent=2)}")
    
    else:
        print("🔗 Firewall Webhook Client")
        print("Use --demo to see example usage")
        print("Use --test-url <url> to send test webhook")

if __name__ == '__main__':
    main()
