#!/usr/bin/env python3
"""
Generate Controlled Benign Traffic PCAP
Creates normal DNS traffic with known characteristics for validation testing
"""

from scapy.all import *
import time
import random
import os

def create_benign_simple_pcap(output_file):
    """
    Create simple single query/response PCAP for basic validation
    
    Known Ground Truth:
    - Exactly 1 query, 1 response
    - Query type: A (1)
    - Known byte counts
    """
    print(f"[*] Creating Simple Benign PCAP: {output_file}")
    
    packets = []
    base_time = time.time()
    
    # Single DNS query
    query = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
            IP(src="192.168.1.50", dst="8.8.8.8") / \
            UDP(sport=54321, dport=53) / \
            DNS(id=1234, rd=1, qd=DNSQR(qname="example.com", qtype=1))
    
    query.time = base_time
    packets.append(query)
    
    # Single DNS response
    response = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / \
               IP(src="8.8.8.8", dst="192.168.1.50") / \
               UDP(sport=53, dport=54321) / \
               DNS(id=1234, qr=1, aa=0, rd=1, ra=1,
                   qd=DNSQR(qname="example.com", qtype=1),
                   an=DNSRR(rrname="example.com", ttl=300, rdata="93.184.216.34"))
    
    response.time = base_time + 0.025  # 25ms response time
    packets.append(response)
    
    wrpcap(output_file, packets)
    
    query_bytes = len(query)
    response_bytes = len(response)
    
    print(f"\n[+] PCAP created successfully!")
    print(f"\n    GROUND TRUTH VALUES:")
    print(f"    ==================")
    print(f"    Total Queries:          1")
    print(f"    Total Responses:        1")
    print(f"    Query Bytes:            {query_bytes}")
    print(f"    Response Bytes:         {response_bytes}")
    print(f"    Amplification Factor:   {response_bytes/query_bytes:.2f}x")
    print(f"    Response Time:          25.0 ms")
    print(f"    Flow Duration:          25.0 ms")
    print(f"    Total Packets:          2")
    print(f"    Fwd Packets:            1")
    print(f"    Bwd Packets:            1")
    
    return {
        'dns_total_queries': 1,
        'dns_total_responses': 1,
        'total_fwd_packets': 1,
        'total_bwd_packets': 1,
        'total_fwd_bytes': query_bytes,
        'total_bwd_bytes': response_bytes,
        'dns_amplification_factor': response_bytes/query_bytes,
        'query_response_ratio': 1.0,
        'flow_duration': 25.0,  # milliseconds
        'dns_any_query_ratio': 0.0,
        'dns_txt_query_ratio': 0.0
    }

def create_benign_normal_browsing_pcap(output_file, duration=60, users=5):
    """
    Create realistic benign browsing traffic PCAP
    
    Known Ground Truth:
    - Multiple users with varied query patterns
    - Normal query types: A (70%), AAAA (20%), MX (5%), TXT (5%)
    - Balanced query/response ratio (~1:1)
    - Varied inter-arrival times
    """
    print(f"\n[*] Creating Normal Browsing PCAP: {output_file}")
    print(f"    Duration: {duration}s, Simulated Users: {users}")
    
    packets = []
    base_time = time.time()
    
    # Common domains for normal browsing
    normal_domains = [
        'google.com', 'facebook.com', 'youtube.com', 'twitter.com',
        'linkedin.com', 'github.com', 'stackoverflow.com', 'amazon.com',
        'netflix.com', 'wikipedia.org', 'reddit.com', 'microsoft.com'
    ]
    
    # Query type distribution for benign traffic
    query_type_dist = {
        1: 0.70,    # A - 70%
        28: 0.20,   # AAAA - 20%
        15: 0.05,   # MX - 5%
        16: 0.05    # TXT - 5%
    }
    
    query_count = 0
    response_count = 0
    query_type_counts = {1: 0, 28: 0, 15: 0, 16: 0}
    
    # Simulate browsing sessions
    for user_id in range(users):
        user_ip = f"192.168.1.{50 + user_id}"
        
        # Each user makes 15-25 queries
        num_queries = random.randint(15, 25)
        
        for i in range(num_queries):
            # Variable timing (human-like)
            timestamp = base_time + random.uniform(0, duration)
            
            domain = random.choice(normal_domains)
            
            # Select query type based on distribution
            rand = random.random()
            if rand < 0.70:
                qtype = 1  # A
            elif rand < 0.90:
                qtype = 28  # AAAA
            elif rand < 0.95:
                qtype = 15  # MX
            else:
                qtype = 16  # TXT
            
            query_type_counts[qtype] += 1
            
            # Create query
            sport = random.randint(49152, 65535)
            tx_id = random.randint(1, 65535)
            
            query = Ether(src=f"00:11:22:33:44:{user_id:02x}", dst="aa:bb:cc:dd:ee:ff") / \
                    IP(src=user_ip, dst="8.8.8.8") / \
                    UDP(sport=sport, dport=53) / \
                    DNS(id=tx_id, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
            
            query.time = timestamp
            packets.append(query)
            query_count += 1
            
            # Normal traffic: 95% response rate
            if random.random() < 0.95:
                # Create response
                response = Ether(src="aa:bb:cc:dd:ee:ff", dst=f"00:11:22:33:44:{user_id:02x}") / \
                          IP(src="8.8.8.8", dst=user_ip) / \
                          UDP(sport=53, dport=sport) / \
                          DNS(id=tx_id, qr=1, aa=0, rd=1, ra=1,
                              qd=DNSQR(qname=domain, qtype=qtype),
                              an=DNSRR(rrname=domain, ttl=300, rdata="93.184.216.34"))
                
                # Normal response time: 10-50ms
                response.time = timestamp + random.uniform(0.010, 0.050)
                packets.append(response)
                response_count += 1
    
    # Sort packets by timestamp
    packets.sort(key=lambda p: p.time)
    
    wrpcap(output_file, packets)
    
    total_query_bytes = sum(len(p) for p in packets if DNS in p and p[DNS].qr == 0)
    total_response_bytes = sum(len(p) for p in packets if DNS in p and p[DNS].qr == 1)
    
    print(f"\n[+] PCAP created successfully!")
    print(f"\n    GROUND TRUTH VALUES:")
    print(f"    ==================")
    print(f"    Total Queries:          {query_count}")
    print(f"    Total Responses:        {response_count}")
    print(f"    Query Type A:           {query_type_counts[1]} ({query_type_counts[1]/query_count*100:.1f}%)")
    print(f"    Query Type AAAA:        {query_type_counts[28]} ({query_type_counts[28]/query_count*100:.1f}%)")
    print(f"    Query Type MX:          {query_type_counts[15]} ({query_type_counts[15]/query_count*100:.1f}%)")
    print(f"    Query Type TXT:         {query_type_counts[16]} ({query_type_counts[16]/query_count*100:.1f}%)")
    print(f"    TXT Query Ratio:        {query_type_counts[16]/query_count:.4f}")
    print(f"    ANY Query Ratio:        0.0000 (no ANY queries)")
    print(f"    Query/Response Ratio:   {query_count/response_count:.2f}")
    print(f"    Amplification Factor:   {total_response_bytes/total_query_bytes:.2f}x")
    print(f"    Queries Per Second:     {query_count/duration:.2f}")
    print(f"    Total Packets:          {len(packets)}")
    
    return {
        'dns_total_queries': query_count,
        'dns_total_responses': response_count,
        'dns_any_query_ratio': 0.0,
        'dns_txt_query_ratio': query_type_counts[16]/query_count,
        'query_response_ratio': query_count/response_count,
        'dns_amplification_factor': total_response_bytes/total_query_bytes,
        'dns_queries_per_second': query_count/duration
    }

def main():
    print("""
===============================================================
     CONTROLLED BENIGN TRAFFIC PCAP GENERATOR
                 For Validation Testing
===============================================================
""")
    
    output_dir = "test_pcaps"
    os.makedirs(output_dir, exist_ok=True)
    
    print("[*] Generating benign traffic PCAPs...\n")
    
    # 1. Simple single query/response
    simple_file = os.path.join(output_dir, "benign_dns_simple.pcap")
    simple_truth = create_benign_simple_pcap(simple_file)
    
    # 2. Normal browsing traffic
    browsing_file = os.path.join(output_dir, "benign_normal_browsing.pcap")
    browsing_truth = create_benign_normal_browsing_pcap(browsing_file, duration=60, users=5)
    
    # Save ground truth
    truth_file = os.path.join(output_dir, "benign_ground_truth.txt")
    with open(truth_file, 'w') as f:
        f.write("BENIGN TRAFFIC - GROUND TRUTH VALUES\n")
        f.write("=" * 60 + "\n\n")
        
        f.write("1. benign_dns_simple.pcap\n")
        f.write("-" * 40 + "\n")
        for key, value in simple_truth.items():
            f.write(f"{key}: {value}\n")
        
        f.write("\n2. benign_normal_browsing.pcap\n")
        f.write("-" * 40 + "\n")
        for key, value in browsing_truth.items():
            f.write(f"{key}: {value}\n")
    
    print(f"\n\n{'='*60}")
    print("[SUCCESS] All benign PCAPs generated!")
    print(f"{'='*60}")
    print(f"\nOutput directory: {os.path.abspath(output_dir)}")
    print(f"\nFiles created:")
    print(f"  1. {simple_file}")
    print(f"  2. {browsing_file}")
    print(f"  3. {truth_file} (ground truth values)")
    print(f"\n[NEXT] Run CIC-Flow-Meter-DNS on these PCAPs and validate output")

if __name__ == '__main__':
    main()
