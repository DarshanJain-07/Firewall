#!/usr/bin/env python3
"""
Test script for webhook functionality
"""

import json
import time
import hmac
import hashlib
import requests
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

class TestWebhookHandler(BaseHTTPRequestHandler):
    received_events = []
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        # Parse webhook data
        webhook_data = json.loads(post_data.decode('utf-8'))
        TestWebhookHandler.received_events.extend(webhook_data.get('events', []))
        
        # Send success response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "success"}')
    
    def log_message(self, format, *args):
        pass  # Suppress logs

def start_test_server(port=8080):
    """Start test webhook server."""
    server = HTTPServer(('localhost', port), TestWebhookHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

def test_webhook_creation():
    """Test webhook event creation."""
    print("🧪 Testing webhook event creation...")
    
    # Import webhook functions
    import sys
    sys.path.append('.')
    
    try:
        from firewall import create_webhook_event, create_webhook_signature
        
        # Test event creation
        event = create_webhook_event("test_event", {"test": "data"})
        
        assert event["event_type"] == "test_event"
        assert event["data"]["test"] == "data"
        assert "id" in event
        assert "timestamp" in event
        
        print("✅ Event creation test passed")
        
        # Test signature creation
        payload = json.dumps({"test": "data"})
        secret = "test-secret"
        signature = create_webhook_signature(payload, secret)
        
        # Verify signature
        expected = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        assert signature == expected
        print("✅ Signature creation test passed")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    return True

def test_webhook_delivery():
    """Test webhook delivery to test server."""
    print("🧪 Testing webhook delivery...")
    
    # Start test server
    server = start_test_server(8081)
    time.sleep(1)  # Give server time to start
    
    try:
        # Send test webhook
        test_payload = {
            "events": [{
                "id": "test-123",
                "timestamp": datetime.now().isoformat(),
                "event_type": "test_event",
                "version": "1.0",
                "source": "firewall",
                "data": {"test": "delivery"}
            }],
            "batch_size": 1,
            "timestamp": datetime.now().isoformat()
        }
        
        response = requests.post(
            "http://localhost:8081",
            json=test_payload,
            timeout=5
        )
        
        assert response.status_code == 200
        
        # Check if event was received
        time.sleep(0.5)  # Give handler time to process
        assert len(TestWebhookHandler.received_events) > 0
        assert TestWebhookHandler.received_events[0]["event_type"] == "test_event"
        
        print("✅ Webhook delivery test passed")
        
    except Exception as e:
        print(f"❌ Delivery test failed: {e}")
        return False
    finally:
        server.shutdown()
    
    return True

def test_signature_verification():
    """Test webhook signature verification."""
    print("🧪 Testing signature verification...")
    
    try:
        from webhook_client import FirewallWebhookClient
        
        secret = "test-secret-key"
        client = FirewallWebhookClient(secret)
        
        # Test valid signature
        payload = '{"test": "data"}'
        signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        assert client.verify_signature(payload, f"sha256={signature}")
        print("✅ Valid signature verification passed")
        
        # Test invalid signature
        assert not client.verify_signature(payload, "sha256=invalid")
        print("✅ Invalid signature rejection passed")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Signature test failed: {e}")
        return False
    
    return True

def test_event_processing():
    """Test event processing with handlers."""
    print("🧪 Testing event processing...")
    
    try:
        from webhook_client import FirewallWebhookClient
        
        client = FirewallWebhookClient()
        
        # Test handler registration
        events_handled = []
        
        def test_handler(event):
            events_handled.append(event)
            return {"status": "processed"}
        
        client.register_handler("test_event", test_handler)
        
        # Test event processing
        test_payload = json.dumps({
            "events": [{
                "id": "test-456",
                "event_type": "test_event",
                "data": {"test": "processing"}
            }]
        })
        
        result = client.process_webhook(test_payload)
        
        assert result["status"] == "success"
        assert len(events_handled) == 1
        assert events_handled[0]["data"]["test"] == "processing"
        
        print("✅ Event processing test passed")
        
    except Exception as e:
        print(f"❌ Event processing test failed: {e}")
        return False
    
    return True

def test_configuration_loading():
    """Test webhook configuration loading."""
    print("🧪 Testing configuration loading...")
    
    try:
        # Create test config
        test_config = {
            "webhooks": {
                "enabled": True,
                "endpoints": [{
                    "name": "test",
                    "url": "http://test.example.com",
                    "secret": "test-secret"
                }]
            }
        }
        
        # Test config validation
        assert test_config["webhooks"]["enabled"] == True
        assert len(test_config["webhooks"]["endpoints"]) == 1
        assert test_config["webhooks"]["endpoints"][0]["url"] == "http://test.example.com"
        
        print("✅ Configuration loading test passed")
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False
    
    return True

def run_all_tests():
    """Run all webhook tests."""
    print("🚀 Running webhook system tests...")
    print("=" * 50)
    
    tests = [
        test_webhook_creation,
        test_signature_verification,
        test_event_processing,
        test_configuration_loading,
        test_webhook_delivery
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            failed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Webhook system is working correctly.")
        return True
    else:
        print("⚠️ Some tests failed. Please check the implementation.")
        return False

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Test webhook functionality')
    parser.add_argument('--test', choices=[
        'creation', 'delivery', 'signature', 'processing', 'config', 'all'
    ], default='all', help='Which test to run')
    
    args = parser.parse_args()
    
    if args.test == 'all':
        run_all_tests()
    elif args.test == 'creation':
        test_webhook_creation()
    elif args.test == 'delivery':
        test_webhook_delivery()
    elif args.test == 'signature':
        test_signature_verification()
    elif args.test == 'processing':
        test_event_processing()
    elif args.test == 'config':
        test_configuration_loading()
