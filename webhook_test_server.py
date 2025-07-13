#!/usr/bin/env python3
"""
Webhook Test Server for Firewall
A simple HTTP server to receive and display webhook events from the firewall.
"""

import json
import hmac
import hashlib
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import argparse

class WebhookHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, webhook_secret=None, **kwargs):
        self.webhook_secret = webhook_secret
        super().__init__(*args, **kwargs)

    def do_POST(self):
        """Handle incoming webhook POST requests."""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "Empty request body")
                return

            # Read the request body
            post_data = self.rfile.read(content_length)
            payload = post_data.decode('utf-8')

            # Verify signature if secret is configured
            if self.webhook_secret:
                signature_header = self.headers.get('X-Firewall-Signature')
                if not signature_header:
                    self.send_error(401, "Missing signature header")
                    return

                if not self.verify_signature(payload, signature_header):
                    self.send_error(401, "Invalid signature")
                    return

            # Parse JSON payload
            try:
                webhook_data = json.loads(payload)
            except json.JSONDecodeError as e:
                self.send_error(400, f"Invalid JSON: {e}")
                return

            # Process the webhook
            self.process_webhook(webhook_data)

            # Send success response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {"status": "success", "message": "Webhook received"}
            self.wfile.write(json.dumps(response).encode())

        except Exception as e:
            print(f"Error processing webhook: {e}")
            self.send_error(500, f"Internal server error: {e}")

    def verify_signature(self, payload, signature_header):
        """Verify HMAC-SHA256 signature."""
        if not signature_header.startswith('sha256='):
            return False

        received_signature = signature_header[7:]  # Remove 'sha256=' prefix
        expected_signature = hmac.new(
            self.webhook_secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(received_signature, expected_signature)

    def process_webhook(self, webhook_data):
        """Process and display webhook data."""
        print("\n" + "="*80)
        print(f"🔔 WEBHOOK RECEIVED at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)

        # Display batch information
        batch_size = webhook_data.get('batch_size', 1)
        print(f"📦 Batch Size: {batch_size} events")
        print(f"⏰ Batch Timestamp: {webhook_data.get('timestamp', 'N/A')}")

        # Process each event in the batch
        events = webhook_data.get('events', [])
        for i, event in enumerate(events, 1):
            print(f"\n📋 Event {i}/{batch_size}:")
            print(f"   🆔 ID: {event.get('id', 'N/A')}")
            print(f"   📅 Timestamp: {event.get('timestamp', 'N/A')}")
            print(f"   🏷️  Type: {event.get('event_type', 'N/A')}")
            print(f"   📦 Version: {event.get('version', 'N/A')}")
            print(f"   🔧 Source: {event.get('source', 'N/A')}")

            # Display event data
            data = event.get('data', {})
            if data:
                print("   📊 Data:")
                for key, value in data.items():
                    if isinstance(value, list) and len(value) > 5:
                        # Truncate long lists
                        print(f"      {key}: {value[:5]}... ({len(value)} total)")
                    else:
                        print(f"      {key}: {value}")

            # Add specific handling for different event types
            self.handle_specific_event(event)

        print("\n" + "="*80)

    def handle_specific_event(self, event):
        """Handle specific event types with custom logic."""
        event_type = event.get('event_type')
        data = event.get('data', {})

        if event_type == 'ip_blocked':
            ip = data.get('ip', 'Unknown')
            reason = data.get('reason', 'Unknown')
            print(f"   🚫 ALERT: IP {ip} blocked for {reason}")

        elif event_type == 'port_scanning_detected':
            ip = data.get('ip', 'Unknown')
            ports = data.get('unique_ports_scanned', 0)
            print(f"   🔍 ALERT: Port scanning detected from {ip} ({ports} ports)")

        elif event_type == 'distributed_attack_detected':
            ip = data.get('ip', 'Unknown')
            port = data.get('port', 'Unknown')
            attempts = data.get('attempts', 0)
            print(f"   ⚡ ALERT: Distributed attack on port {port} from {ip} ({attempts} attempts)")

        elif event_type == 'firewall_started':
            mode = data.get('mode', 'Unknown')
            print(f"   🚀 INFO: Firewall started in {mode} mode")

        elif event_type in ['block_error', 'unblock_error']:
            ip = data.get('ip', 'Unknown')
            error = data.get('error', 'Unknown')
            print(f"   ❌ ERROR: {event_type} for IP {ip}: {error}")

    def log_message(self, format, *args):
        """Override to reduce noise in logs."""
        pass  # Suppress default HTTP server logs

def create_handler_class(webhook_secret):
    """Create a handler class with the webhook secret."""
    class CustomWebhookHandler(WebhookHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, webhook_secret=webhook_secret, **kwargs)
    return CustomWebhookHandler

def main():
    parser = argparse.ArgumentParser(description='Webhook Test Server for Firewall')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--secret', help='Webhook secret for signature verification')
    
    args = parser.parse_args()

    # Create handler class with secret
    handler_class = create_handler_class(args.secret)

    # Create and start server
    server = HTTPServer((args.host, args.port), handler_class)
    
    print(f"🔗 Webhook Test Server starting on http://{args.host}:{args.port}")
    if args.secret:
        print(f"🔐 Signature verification enabled with secret")
    else:
        print(f"⚠️  No secret provided - signature verification disabled")
    
    print(f"📡 Ready to receive firewall webhooks...")
    print(f"💡 Use Ctrl+C to stop the server")
    print("\n" + "="*80)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n🛑 Shutting down webhook server...")
        server.shutdown()

if __name__ == '__main__':
    main()
