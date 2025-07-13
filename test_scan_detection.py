#!/usr/bin/env python3
"""
Test script for verifying different TCP scan type detection.
This script simulates various scan types to test the firewall's detection capabilities.
"""

from scapy.all import *
import time
import sys
import argparse

def test_syn_scan(target_ip, target_port):
    """Test SYN scan detection."""
    print(f"🔍 Testing SYN scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(packet, verbose=0)
    print("✅ SYN packet sent")

def test_fin_scan(target_ip, target_port):
    """Test FIN scan detection."""
    print(f"🔍 Testing FIN scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="F")
    send(packet, verbose=0)
    print("✅ FIN packet sent")

def test_null_scan(target_ip, target_port):
    """Test NULL scan detection."""
    print(f"🔍 Testing NULL scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="")
    send(packet, verbose=0)
    print("✅ NULL packet sent")

def test_xmas_scan(target_ip, target_port):
    """Test XMAS scan detection."""
    print(f"🔍 Testing XMAS scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FPU")
    send(packet, verbose=0)
    print("✅ XMAS packet sent")

def test_ack_scan(target_ip, target_port):
    """Test ACK scan detection."""
    print(f"🔍 Testing ACK scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="A")
    send(packet, verbose=0)
    print("✅ ACK packet sent")

def test_maimon_scan(target_ip, target_port):
    """Test Maimon scan detection."""
    print(f"🔍 Testing Maimon scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FA")
    send(packet, verbose=0)
    print("✅ Maimon packet sent")

def test_rst_scan(target_ip, target_port):
    """Test RST scan detection."""
    print(f"🔍 Testing RST scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="R")
    send(packet, verbose=0)
    print("✅ RST packet sent")

def test_psh_scan(target_ip, target_port):
    """Test PSH scan detection."""
    print(f"🔍 Testing PSH scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="P")
    send(packet, verbose=0)
    print("✅ PSH packet sent")

def test_urg_scan(target_ip, target_port):
    """Test URG scan detection."""
    print(f"🔍 Testing URG scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="U")
    send(packet, verbose=0)
    print("✅ URG packet sent")

def test_custom_scan(target_ip, target_port):
    """Test custom flag combination scan detection."""
    print(f"🔍 Testing custom scan to {target_ip}:{target_port}")
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FPAU")
    send(packet, verbose=0)
    print("✅ Custom packet sent")

def test_port_scanning(target_ip, ports):
    """Test port scanning detection by hitting multiple ports."""
    print(f"🔍 Testing port scanning to {target_ip} on ports {ports}")
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.1)  # Small delay between packets
    print(f"✅ Port scan completed on {len(ports)} ports")

def test_suspicious_scanning(target_ip, target_port):
    """Test suspicious scanning detection by sending multiple suspicious scans."""
    print(f"🔍 Testing suspicious scanning detection to {target_ip}:{target_port}")
    
    # Send multiple suspicious scans to trigger detection
    scans = [
        ("FIN", "F"),
        ("NULL", ""),
        ("XMAS", "FPU"),
        ("ACK", "A"),
        ("Maimon", "FA")
    ]
    
    for scan_name, flags in scans:
        print(f"  Sending {scan_name} scan...")
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags=flags)
        send(packet, verbose=0)
        time.sleep(0.5)  # Delay between scans
    
    print("✅ Suspicious scanning test completed")

def main():
    parser = argparse.ArgumentParser(description="Test TCP scan detection")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--scan-type", "-s", choices=[
        "syn", "fin", "null", "xmas", "ack", "maimon", "rst", "psh", "urg", "custom",
        "port-scan", "suspicious", "all"
    ], default="all", help="Type of scan to test")
    parser.add_argument("--delay", "-d", type=float, default=1.0, help="Delay between tests (seconds)")
    
    args = parser.parse_args()
    
    print("="*60)
    print("🔍 TCP SCAN DETECTION TEST SUITE")
    print("="*60)
    print(f"Target: {args.target_ip}:{args.port}")
    print(f"Scan type: {args.scan_type}")
    print(f"Delay: {args.delay}s")
    print("="*60)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️ Warning: This script should be run as root for packet crafting")
        print("   Use: sudo python3 test_scan_detection.py <target_ip>")
    
    try:
        if args.scan_type == "syn" or args.scan_type == "all":
            test_syn_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "fin" or args.scan_type == "all":
            test_fin_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "null" or args.scan_type == "all":
            test_null_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "xmas" or args.scan_type == "all":
            test_xmas_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "ack" or args.scan_type == "all":
            test_ack_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "maimon" or args.scan_type == "all":
            test_maimon_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "rst" or args.scan_type == "all":
            test_rst_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "psh" or args.scan_type == "all":
            test_psh_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "urg" or args.scan_type == "all":
            test_urg_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "custom" or args.scan_type == "all":
            test_custom_scan(args.target_ip, args.port)
            time.sleep(args.delay)
        
        if args.scan_type == "port-scan" or args.scan_type == "all":
            # Test port scanning on multiple ports
            ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            test_port_scanning(args.target_ip, ports)
            time.sleep(args.delay)
        
        if args.scan_type == "suspicious" or args.scan_type == "all":
            test_suspicious_scanning(args.target_ip, args.port)
            time.sleep(args.delay)
        
        print("\n✅ All tests completed!")
        print("Check the firewall logs to verify detection.")
        
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
    except Exception as e:
        print(f"❌ Error during testing: {e}")

if __name__ == "__main__":
    import os
    main()
