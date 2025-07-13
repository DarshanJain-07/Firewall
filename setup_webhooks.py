#!/usr/bin/env python3
"""
Webhook Setup Script
Helps organizations configure webhook integration with the firewall.
"""

import os
import json
import secrets
import argparse
from urllib.parse import urlparse

def generate_webhook_secret():
    """Generate a secure webhook secret."""
    return secrets.token_urlsafe(32)

def validate_url(url):
    """Validate webhook URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def create_webhook_config():
    """Interactive webhook configuration."""
    print("🔗 Firewall Webhook Configuration Setup")
    print("="*50)
    
    config = {
        "webhooks": {
            "enabled": True,
            "retry_attempts": 3,
            "retry_delay": 5,
            "timeout": 10,
            "batch_size": 10,
            "batch_timeout": 30,
            "rate_limit": 100,
            "signature_header": "X-Firewall-Signature",
            "timestamp_header": "X-Firewall-Timestamp",
            "endpoints": []
        }
    }
    
    print("\n📋 Basic Configuration")
    
    # Batch settings
    batch_size = input(f"Batch size (events per request) [10]: ").strip()
    if batch_size:
        config["webhooks"]["batch_size"] = int(batch_size)
    
    batch_timeout = input(f"Batch timeout (seconds) [30]: ").strip()
    if batch_timeout:
        config["webhooks"]["batch_timeout"] = int(batch_timeout)
    
    rate_limit = input(f"Rate limit (requests per minute) [100]: ").strip()
    if rate_limit:
        config["webhooks"]["rate_limit"] = int(rate_limit)
    
    # Endpoints
    print("\n🎯 Webhook Endpoints")
    endpoint_count = 1
    
    while True:
        print(f"\n--- Endpoint {endpoint_count} ---")
        
        name = input(f"Endpoint name: ").strip()
        if not name:
            break
        
        url = input(f"Webhook URL: ").strip()
        if not url or not validate_url(url):
            print("❌ Invalid URL, skipping endpoint")
            continue
        
        # Generate or ask for secret
        use_secret = input("Use webhook secret for security? [Y/n]: ").strip().lower()
        secret = None
        if use_secret != 'n':
            provided_secret = input("Enter secret (leave empty to generate): ").strip()
            secret = provided_secret if provided_secret else generate_webhook_secret()
            print(f"🔐 Secret: {secret}")
        
        # Custom headers
        headers = {}
        print("Custom headers (press enter when done):")
        while True:
            header_name = input("  Header name: ").strip()
            if not header_name:
                break
            header_value = input(f"  {header_name} value: ").strip()
            if header_value:
                headers[header_name] = header_value
        
        # Event filtering
        print("\nEvent filtering:")
        print("Available events: firewall_started, connection_attempt, ip_blocked,")
        print("                 ip_unblocked, port_scanning_detected, distributed_attack_detected,")
        print("                 block_error, unblock_error")
        
        filter_events = input("Filter events? [y/N]: ").strip().lower()
        events_config = {}
        
        if filter_events == 'y':
            include_events = input("Events to include (comma-separated): ").strip()
            if include_events:
                events_config["include"] = [e.strip() for e in include_events.split(",")]
            
            exclude_events = input("Events to exclude (comma-separated): ").strip()
            if exclude_events:
                events_config["exclude"] = [e.strip() for e in exclude_events.split(",")]
        
        # Build endpoint config
        endpoint = {
            "name": name,
            "url": url,
            "enabled": True
        }
        
        if secret:
            endpoint["secret"] = secret
        
        if headers:
            endpoint["headers"] = headers
        
        if events_config:
            endpoint["events"] = events_config
        
        config["webhooks"]["endpoints"].append(endpoint)
        endpoint_count += 1
        
        another = input("\nAdd another endpoint? [y/N]: ").strip().lower()
        if another != 'y':
            break
    
    return config

def update_firewall_config(webhook_config):
    """Update firewall_config.toml with webhook configuration."""
    config_file = "firewall_config.toml"
    
    if not os.path.exists(config_file):
        print(f"❌ {config_file} not found. Please run this script from the firewall directory.")
        return False
    
    # Read existing config
    try:
        import tomllib
        with open(config_file, 'rb') as f:
            existing_config = tomllib.load(f)
    except ImportError:
        try:
            import tomli as tomllib
            with open(config_file, 'rb') as f:
                existing_config = tomllib.load(f)
        except ImportError:
            print("❌ TOML library not available. Please install tomli or use Python 3.11+")
            return False
    
    # Merge webhook config
    existing_config.update(webhook_config)
    
    # Write updated config
    try:
        import tomli_w
        with open(config_file, 'wb') as f:
            tomli_w.dump(existing_config, f)
        print(f"✅ Updated {config_file} with webhook configuration")
        return True
    except ImportError:
        print("❌ tomli_w not available. Please install it to update the config file.")
        print("\nGenerated configuration (add to firewall_config.toml manually):")
        print(json.dumps(webhook_config, indent=2))
        return False

def install_dependencies():
    """Install required dependencies for webhooks."""
    print("📦 Installing webhook dependencies...")
    
    dependencies = [
        "aiohttp",
        "requests"
    ]
    
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep} already installed")
        except ImportError:
            print(f"📥 Installing {dep}...")
            os.system(f"pip install {dep}")

def create_systemd_service():
    """Create systemd service file for webhook handler."""
    service_content = """[Unit]
Description=Firewall Webhook Handler
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/firewall
Environment=WEBHOOK_SECRET=your-secret-here
Environment=DATABASE_PATH=/var/lib/firewall/events.db
Environment=EMAIL_USER=alerts@example.com
Environment=EMAIL_PASS=your-email-password
Environment=ALERT_EMAIL=security@example.com
ExecStart=/usr/bin/python3 example_webhook_handler.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    with open("firewall-webhook.service", "w") as f:
        f.write(service_content)
    
    print("✅ Created firewall-webhook.service")
    print("📝 Edit the service file with your actual paths and credentials")
    print("🔧 Install with: sudo cp firewall-webhook.service /etc/systemd/system/")
    print("🚀 Enable with: sudo systemctl enable firewall-webhook")

def main():
    parser = argparse.ArgumentParser(description='Setup webhook integration for firewall')
    parser.add_argument('--interactive', action='store_true', help='Interactive configuration')
    parser.add_argument('--install-deps', action='store_true', help='Install dependencies')
    parser.add_argument('--create-service', action='store_true', help='Create systemd service file')
    parser.add_argument('--test-url', help='Test webhook URL')
    
    args = parser.parse_args()
    
    if args.install_deps:
        install_dependencies()
        return
    
    if args.create_service:
        create_systemd_service()
        return
    
    if args.test_url:
        print(f"🧪 Testing webhook URL: {args.test_url}")
        if validate_url(args.test_url):
            print("✅ URL format is valid")
            # Test connectivity
            try:
                import requests
                response = requests.get(args.test_url, timeout=5)
                print(f"📡 Connection test: {response.status_code}")
            except Exception as e:
                print(f"❌ Connection failed: {e}")
        else:
            print("❌ Invalid URL format")
        return
    
    if args.interactive:
        webhook_config = create_webhook_config()
        
        print("\n📄 Generated Configuration:")
        print(json.dumps(webhook_config, indent=2))
        
        save_config = input("\nSave to firewall_config.toml? [Y/n]: ").strip().lower()
        if save_config != 'n':
            if update_firewall_config(webhook_config):
                print("\n🎉 Webhook configuration complete!")
                print("\n📋 Next steps:")
                print("1. Start your webhook endpoint server")
                print("2. Restart the firewall to load new configuration")
                print("3. Test with: python webhook_client.py --test-url <your-url>")
            else:
                print("\n⚠️  Manual configuration required")
    else:
        print("🔗 Firewall Webhook Setup")
        print("Use --interactive for guided setup")
        print("Use --install-deps to install dependencies")
        print("Use --create-service to create systemd service")
        print("Use --test-url <url> to test webhook connectivity")

if __name__ == '__main__':
    main()
