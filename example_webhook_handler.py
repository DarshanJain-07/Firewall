#!/usr/bin/env python3
"""
Example Webhook Handler for Organizations
A production-ready webhook handler that organizations can customize.
"""

import json
import hmac
import hashlib
import sqlite3
import smtplib
import logging
from datetime import datetime
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from flask import Flask, request, jsonify
import requests
import os

# Configuration
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'your-secret-key-here')
DATABASE_PATH = os.getenv('DATABASE_PATH', 'firewall_events.db')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASS = os.getenv('EMAIL_PASS', '')
ALERT_EMAIL = os.getenv('ALERT_EMAIL', 'security@example.com')
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webhook_handler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class FirewallEventHandler:
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for storing events."""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                timestamp TEXT,
                event_type TEXT,
                ip_address TEXT,
                data TEXT,
                processed_at TEXT,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                first_blocked TEXT,
                last_blocked TEXT,
                block_count INTEGER,
                reasons TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def verify_signature(self, payload, signature):
        """Verify webhook signature."""
        if not signature or not signature.startswith('sha256='):
            return False
        
        received_signature = signature[7:]  # Remove 'sha256=' prefix
        expected_signature = hmac.new(
            WEBHOOK_SECRET.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(received_signature, expected_signature)
    
    def store_event(self, event):
        """Store event in database."""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO firewall_events 
                (event_id, timestamp, event_type, ip_address, data, processed_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('id'),
                event.get('timestamp'),
                event.get('event_type'),
                event.get('data', {}).get('ip', ''),
                json.dumps(event.get('data', {})),
                datetime.now().isoformat(),
                'processed'
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"Error storing event: {e}")
        finally:
            conn.close()
    
    def update_blocked_ips(self, ip, reason):
        """Update blocked IPs tracking."""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            # Check if IP already exists
            cursor.execute('SELECT * FROM blocked_ips WHERE ip_address = ?', (ip,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                reasons = json.loads(existing[4]) if existing[4] else []
                if reason not in reasons:
                    reasons.append(reason)
                
                cursor.execute('''
                    UPDATE blocked_ips 
                    SET last_blocked = ?, block_count = block_count + 1, reasons = ?
                    WHERE ip_address = ?
                ''', (datetime.now().isoformat(), json.dumps(reasons), ip))
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO blocked_ips 
                    (ip_address, first_blocked, last_blocked, block_count, reasons)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    ip,
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    1,
                    json.dumps([reason])
                ))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error updating blocked IPs: {e}")
        finally:
            conn.close()
    
    def send_email_alert(self, subject, body):
        """Send email alert."""
        if not EMAIL_USER or not EMAIL_PASS or not ALERT_EMAIL:
            logger.warning("Email configuration missing, skipping email alert")
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = EMAIL_USER
            msg['To'] = ALERT_EMAIL
            msg['Subject'] = subject
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent: {subject}")
        except Exception as e:
            logger.error(f"Error sending email: {e}")
    
    def send_slack_alert(self, message):
        """Send Slack alert."""
        if not SLACK_WEBHOOK_URL:
            logger.warning("Slack webhook URL not configured, skipping Slack alert")
            return
        
        try:
            payload = {"text": message}
            response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
            else:
                logger.error(f"Slack alert failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
    
    def handle_ip_blocked(self, event):
        """Handle IP blocked events."""
        data = event.get('data', {})
        ip = data.get('ip')
        reason = data.get('reason')
        block_count = data.get('block_count', 1)
        
        logger.info(f"IP blocked: {ip} (reason: {reason}, count: {block_count})")
        
        # Store in database
        self.update_blocked_ips(ip, reason)
        
        # Send alerts for repeat offenders
        if block_count >= 3:
            subject = f"CRITICAL: Repeat Offender IP Blocked - {ip}"
            body = f"""
            A repeat offender IP has been blocked:
            
            IP Address: {ip}
            Reason: {reason}
            Block Count: {block_count}
            Timestamp: {event.get('timestamp')}
            
            This IP has been blocked {block_count} times and may require manual investigation.
            """
            
            self.send_email_alert(subject, body)
            self.send_slack_alert(f"🚨 CRITICAL: Repeat offender {ip} blocked ({block_count} times)")
    
    def handle_port_scanning(self, event):
        """Handle port scanning detection."""
        data = event.get('data', {})
        ip = data.get('ip')
        ports_scanned = data.get('unique_ports_scanned', 0)
        ports = data.get('ports', [])
        
        logger.warning(f"Port scanning detected: {ip} scanned {ports_scanned} ports")
        
        # Send alert for extensive scanning
        if ports_scanned >= 10:
            subject = f"HIGH PRIORITY: Extensive Port Scanning - {ip}"
            body = f"""
            Extensive port scanning detected:
            
            IP Address: {ip}
            Ports Scanned: {ports_scanned}
            Ports: {', '.join(map(str, ports[:20]))}{'...' if len(ports) > 20 else ''}
            Timestamp: {event.get('timestamp')}
            
            This may indicate a serious reconnaissance attempt.
            """
            
            self.send_email_alert(subject, body)
            self.send_slack_alert(f"⚠️ Extensive port scanning from {ip} ({ports_scanned} ports)")
    
    def handle_distributed_attack(self, event):
        """Handle distributed attack detection."""
        data = event.get('data', {})
        ip = data.get('ip')
        port = data.get('port')
        attempts = data.get('attempts', 0)
        
        logger.critical(f"Distributed attack detected: {ip} attacking port {port} ({attempts} attempts)")
        
        # Always send alert for distributed attacks
        subject = f"CRITICAL: Distributed Attack Detected - Port {port}"
        body = f"""
        Distributed attack detected:
        
        Source IP: {ip}
        Target Port: {port}
        Attempts: {attempts}
        Timestamp: {event.get('timestamp')}
        
        This indicates a coordinated attack and requires immediate attention.
        """
        
        self.send_email_alert(subject, body)
        self.send_slack_alert(f"🚨 CRITICAL: Distributed attack on port {port} from {ip}")
    
    def process_event(self, event):
        """Process a single event."""
        event_type = event.get('event_type')
        
        # Store all events
        self.store_event(event)
        
        # Handle specific event types
        if event_type == 'ip_blocked':
            self.handle_ip_blocked(event)
        elif event_type == 'port_scanning_detected':
            self.handle_port_scanning(event)
        elif event_type == 'distributed_attack_detected':
            self.handle_distributed_attack(event)
        elif event_type in ['block_error', 'unblock_error']:
            logger.error(f"Firewall error: {event_type} - {event.get('data', {})}")

# Initialize handler
handler = FirewallEventHandler()

@app.route('/webhook', methods=['POST'])
def webhook_endpoint():
    """Main webhook endpoint."""
    try:
        # Get signature
        signature = request.headers.get('X-Firewall-Signature')
        payload = request.data.decode('utf-8')
        
        # Verify signature
        if not handler.verify_signature(payload, signature):
            logger.warning("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 401
        
        # Parse payload
        webhook_data = json.loads(payload)
        events = webhook_data.get('events', [])
        
        logger.info(f"Received webhook with {len(events)} events")
        
        # Process each event
        for event in events:
            try:
                handler.process_event(event)
            except Exception as e:
                logger.error(f"Error processing event {event.get('id')}: {e}")
        
        return jsonify({
            "status": "success",
            "processed_events": len(events)
        })
    
    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get statistics about processed events."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Get event counts by type
        cursor.execute('''
            SELECT event_type, COUNT(*) 
            FROM firewall_events 
            GROUP BY event_type
        ''')
        event_counts = dict(cursor.fetchall())
        
        # Get blocked IP count
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        blocked_ip_count = cursor.fetchone()[0]
        
        # Get recent events
        cursor.execute('''
            SELECT event_type, timestamp, ip_address 
            FROM firewall_events 
            ORDER BY processed_at DESC 
            LIMIT 10
        ''')
        recent_events = cursor.fetchall()
        
        return jsonify({
            "event_counts": event_counts,
            "blocked_ip_count": blocked_ip_count,
            "recent_events": recent_events
        })
    
    finally:
        conn.close()

if __name__ == '__main__':
    logger.info("Starting webhook handler server...")
    app.run(host='0.0.0.0', port=5000, debug=False)
