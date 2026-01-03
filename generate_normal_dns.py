"""
Normal DNS Traffic Generator
Generates realistic benign DNS queries for model testing
"""

import dns.resolver
import time
import random
import sys

# Realistic domains for normal browsing
POPULAR_DOMAINS = [
    # Social Media
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com',
    # Video Streaming
    'youtube.com', 'netflix.com', 'twitch.tv', 'vimeo.com',
    # Search & Tech
    'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
    # E-commerce
    'amazon.com', 'ebay.com', 'walmart.com', 'alibaba.com',
    # News & Info
    'cnn.com', 'bbc.com', 'wikipedia.org', 'medium.com',
    # Developer
    'github.com', 'stackoverflow.com', 'gitlab.com', 'npmjs.com'
]

def generate_normal_traffic(qps=50, duration=60, dns_server='8.8.8.8'):
    """
    Generate normal DNS traffic patterns
    
    Args:
        qps: Queries per second (10-200 is realistic)
        duration: Duration in seconds
        dns_server: DNS server to query
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    resolver.timeout = 2
    resolver.lifetime = 2
    
    queries_sent = 0
    queries_success = 0
    start_time = time.time()
    
    print("=" * 60)
    print("NORMAL DNS TRAFFIC GENERATOR")
    print("=" * 60)
    print(f"Target DNS: {dns_server}")
    print(f"Rate: {qps} queries/second")
    print(f"Duration: {duration} seconds")
    print(f"Expected total: ~{qps * duration} queries")
    print("\nPress Ctrl+C to stop early...")
    print("=" * 60)
    
    try:
        while time.time() - start_time < duration:
            domain = random.choice(POPULAR_DOMAINS)
            
            # Realistic query type distribution
            # 70% A records, 20% AAAA (IPv6), 10% other
            rand = random.random()
            if rand < 0.7:
                qtype = 'A'
            elif rand < 0.9:
                qtype = 'AAAA'
            else:
                qtype = random.choice(['MX', 'TXT', 'NS'])
            
            try:
                answers = resolver.resolve(domain, qtype)
                queries_sent += 1
                queries_success += 1
                
                if queries_sent % 100 == 0:
                    elapsed = time.time() - start_time
                    actual_qps = queries_sent / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.1f}s] Sent: {queries_sent}, Success: {queries_success}, Rate: {actual_qps:.1f} QPS")
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                queries_sent += 1
                # Failed query, but that's normal too
            except Exception as e:
                queries_sent += 1
                # Ignore other errors
            
            # Rate limiting (sleep to maintain QPS)
            time.sleep(1.0 / qps)
            
    except KeyboardInterrupt:
        print("\n\n[STOPPED] User interrupted")
    
    elapsed = time.time() - start_time
    actual_qps = queries_sent / elapsed if elapsed > 0 else 0
    success_rate = (queries_success / queries_sent * 100) if queries_sent > 0 else 0
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total queries: {queries_sent}")
    print(f"Successful: {queries_success} ({success_rate:.1f}%)")
    print(f"Duration: {elapsed:.2f} seconds")
    print(f"Actual rate: {actual_qps:.2f} QPS")
    print("=" * 60)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        qps = int(sys.argv[1])
    else:
        qps = 50  # Default: 50 QPS (normal browsing)
    
    if len(sys.argv) > 2:
        duration = int(sys.argv[2])
    else:
        duration = 60  # Default: 60 seconds
    
    print(f"\nStarting in 3 seconds...")
    print("Make sure your traffic capture tool is running!\n")
    time.sleep(3)
    
    generate_normal_traffic(qps=qps, duration=duration)
