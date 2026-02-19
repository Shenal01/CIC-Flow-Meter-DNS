#!/usr/bin/env python3
"""
Generate Controlled Attack Traffic PCAP
Creates DNS attack traffic with known characteristics for validation testing
"""

from scapy.all import *
import time
import sys
import os

def create_dns_amplification_pcap(output_file, duration=30, rate=100):
    """
    Generate DNS amplification attack PCAP with known characteristics
    
    Known Ground Truth:
    - 100 queries/second for 30 seconds = ~3000 queries
    - Query types: 40% ANY (255), 40% TXT (16), 20% MX (15)
    - Target amplification factor: >10x
    """
    print(f"[*] Creating DNS Amplification PCAP: {output_file}")
    print(f"    Duration: {duration}s, Rate: {rate} QPS")
    
    packets = []
    
    # Amplification domains (known to have large responses)
    amp_domains = ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'cloudflare.com']
    
    # Query type distribution for amplification
    query_types = {
        255: 0.4,  # ANY - 40%
        16: 0.4,   # TXT - 40%
        15: 0.2    # MX - 20%
    }
    
    base_time = time.time()
    interval = 1.0 / rate
    
    query_count = 0
    any_count = 0
    txt_count = 0
    mx_count = 0
    
    for i in range(duration * rate):
        timestamp = base_time + (i * interval)
        
        domain = amp_domains[i % len(amp_domains)]
        
        # Select query type based on distribution
        rand = random.random()
        if rand < 0.4:
            qtype = 255  # ANY
            any_count += 1
        elif rand < 0.8:
            qtype = 16   # TXT
            txt_count += 1
        else:
            qtype = 15   # MX
            mx_count += 1
        
        # Create DNS query
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
              IP(src="192.168.1.100", dst="8.8.8.8") / \
              UDP(sport=random.randint(49152, 65535), dport=53) / \
              DNS(id=i, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
        
        pkt.time = timestamp
        packets.append(pkt)
        query_count += 1
        
        # Simulate response (smaller for amplification attacks - often no response)
        # Only 30% get responses to show high query/response ratio
        if random.random() < 0.3:
            # Simulate large response with multiple answers
            response_pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
                          IP(src="8.8.8.8", dst="192.168.1.100") / \
                          UDP(sport=53, dport=pkt[UDP].sport) / \
                          DNS(id=i, qr=1, aa=0, rd=1, ra=1,
                              qd=DNSQR(qname=domain, qtype=qtype),
                              an=DNSRR(rrname=domain, ttl=300, rdata="93.184.216.34") / \
                                 DNSRR(rrname=domain, ttl=300, rdata="93.184.216.35") / \
                                 DNSRR(rrname=domain, ttl=300, rdata="93.184.216.36"))
            
            response_pkt.time = timestamp + random.uniform(0.01, 0.05)  # Response latency
            packets.append(response_pkt)
    
    # Write PCAP
    wrpcap(output_file, packets)
    
    # Calculate ground truth
    response_count = sum(1 for p in packets if DNS in p and p[DNS].qr == 1)
    total_query_bytes = sum(len(p) for p in packets if DNS in p and p[DNS].qr == 0)
    total_response_bytes = sum(len(p) for p in packets if DNS in p and p[DNS].qr == 1)
    
    print(f"\n[+] PCAP created successfully!")
    print(f"\n    GROUND TRUTH VALUES:")
    print(f"    ==================")
    print(f"    Total Queries:          {query_count}")
    print(f"    Total Responses:        {response_count}")
    print(f"    ANY Queries:            {any_count}")
    print(f"    TXT Queries:            {txt_count}")
    print(f"    MX Queries:             {mx_count}")
    print(f"    ANY Query Ratio:        {any_count/query_count:.4f}")
    print(f"    TXT Query Ratio:        {txt_count/query_count:.4f}")
    print(f"    Query/Response Ratio:   {query_count/response_count:.2f}")
    print(f"    Amplification Factor:   {total_response_bytes/total_query_bytes:.2f}x")
    print(f"    Queries Per Second:     {query_count/duration:.2f}")
    print(f"    Duration:               {duration}s")
    print(f"    Total Packets:          {len(packets)}")
    
    return {
        'dns_total_queries': query_count,
        'dns_total_responses': response_count,
        'dns_any_query_ratio': any_count/query_count,
        'dns_txt_query_ratio': txt_count/query_count,
        'query_response_ratio': query_count/response_count,
        'dns_amplification_factor': total_response_bytes/total_query_bytes,
        'dns_queries_per_second': query_count/duration
    }

def create_dns_flood_pcap(output_file, duration=20, rate=500):
    """
    Generate DNS query flood PCAP
    
    Known Ground Truth:
    - High query rate (500 QPS)
    - Random subdomains (water torture pattern)
    - Very few responses (high query/response ratio)
    """
    print(f"\n[*] Creating DNS Flood PCAP: {output_file}")
    print(f"    Duration: {duration}s, Rate: {rate} QPS")
    
    packets = []
    base_time = time.time()
    interval = 1.0 / rate
    
    query_count = 0
    
    for i in range(duration * rate):
        timestamp = base_time + (i * interval)
        
        # Generate random subdomain (water torture)
        subdomain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(8, 20)))
        domain = f"{subdomain}.nonexistent-attack-test.com"
        
        # Create DNS query
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
              IP(src="192.168.1.100", dst="8.8.8.8") / \
              UDP(sport=random.randint(49152, 65535), dport=53) / \
              DNS(id=i, rd=1, qd=DNSQR(qname=domain, qtype=1))  # Type A
        
        pkt.time = timestamp
        packets.append(pkt)
        query_count += 1
        
        # Very few responses (10%) - flood characteristic
        if random.random() < 0.1:
            response_pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
                          IP(src="8.8.8.8", dst="192.168.1.100") / \
                          UDP(sport=53, dport=pkt[UDP].sport) / \
                          DNS(id=i, qr=1, rcode=3)  # NXDOMAIN
            
            response_pkt.time = timestamp + random.uniform(0.01, 0.03)
            packets.append(response_pkt)
    
    wrpcap(output_file, packets)
    
    response_count = sum(1 for p in packets if DNS in p and p[DNS].qr == 1)
    
    print(f"\n[+] PCAP created successfully!")
    print(f"\n    GROUND TRUTH VALUES:")
    print(f"    ==================")
    print(f"    Total Queries:          {query_count}")
    print(f"    Total Responses:        {response_count}")
    print(f"    Query/Response Ratio:   {query_count/response_count if response_count > 0 else 'Infinite'}")
    print(f"    Queries Per Second:     {query_count/duration:.2f}")
    print(f"    Duration:               {duration}s")
    print(f"    Total Packets:          {len(packets)}")
    
    return {
        'dns_total_queries': query_count,
        'dns_total_responses': response_count,
        'query_response_ratio': query_count/response_count if response_count > 0 else 9999,
        'dns_queries_per_second': query_count/duration
    }

def main():
    print("""
===============================================================
     CONTROLLED ATTACK TRAFFIC PCAP GENERATOR
                 For Validation Testing
===============================================================
""")
    
    output_dir = "test_pcaps"
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate attack PCAPs
    print("[*] Generating attack traffic PCAPs...\n")
    
    # 1. DNS Amplification
    amp_file = os.path.join(output_dir, "attack_dns_amplification.pcap")
    amp_truth = create_dns_amplification_pcap(amp_file, duration=30, rate=100)
    
    # 2. DNS Flood
    flood_file = os.path.join(output_dir, "attack_dns_flood.pcap")
    flood_truth = create_dns_flood_pcap(flood_file, duration=20, rate=500)
    
    # Save ground truth to file for validation
    truth_file = os.path.join(output_dir, "attack_ground_truth.txt")
    with open(truth_file, 'w') as f:
        f.write("ATTACK TRAFFIC - GROUND TRUTH VALUES\n")
        f.write("=" * 60 + "\n\n")
        
        f.write("1. attack_dns_amplification.pcap\n")
        f.write("-" * 40 + "\n")
        for key, value in amp_truth.items():
            f.write(f"{key}: {value}\n")
        
        f.write("\n2. attack_dns_flood.pcap\n")
        f.write("-" * 40 + "\n")
        for key, value in flood_truth.items():
            f.write(f"{key}: {value}\n")
    
    print(f"\n\n{'='*60}")
    print("[SUCCESS] All attack PCAPs generated!")
    print(f"{'='*60}")
    print(f"\nOutput directory: {os.path.abspath(output_dir)}")
    print(f"\nFiles created:")
    print(f"  1. {amp_file}")
    print(f"  2. {flood_file}")
    print(f"  3. {truth_file} (ground truth values)")
    print(f"\n[NEXT] Run the benign traffic generator")

if __name__ == '__main__':
    main()
