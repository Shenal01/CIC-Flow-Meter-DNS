"""
Realistic Benign DNS Traffic Generator
=====================================

Generates realistic benign DNS traffic from simulated users for testing and 
model validation. Creates REAL DNS queries over the network that can be captured
by CIC-Flow-Meter-DNS tool.

Features:
- Simulates at least 10 different users with realistic browsing patterns
- Sends actual DNS queries over the network
- Mimics normal user behavior (web browsing, email, streaming, etc.)
- Realistic timing patterns with delays between queries
- Mix of different record types (A, AAAA, MX, TXT, etc.)
- Configurable duration and intensity

Author: Cybersecurity Data Science Team
Usage:  python generate_realistic_benign_traffic.py --duration 300 --users 15
"""

import socket
import random
import time
import argparse
import threading
from datetime import datetime
import sys

# =============================================================================
# REALISTIC DOMAIN LISTS BY USER ACTIVITY TYPE
# =============================================================================

# Common domains for general browsing
COMMON_WEBSITES = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'reddit.com', 'wikipedia.org', 'github.com',
    'stackoverflow.com', 'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
    'gmail.com', 'yahoo.com', 'bing.com', 'twitch.tv', 'pinterest.com',
    'ebay.com', 'cnn.com', 'bbc.com', 'nytimes.com', 'medium.com'
]

# News and media sites
NEWS_MEDIA = [
    'cnn.com', 'bbc.com', 'nytimes.com', 'theguardian.com', 'reuters.com',
    'wsj.com', 'washingtonpost.com', 'foxnews.com', 'bloomberg.com', 'reuters.com'
]

# Tech and development sites
TECH_SITES = [
    'github.com', 'stackoverflow.com', 'gitlab.com', 'bitbucket.org', 
    'docker.com', 'kubernetes.io', 'python.org', 'npmjs.com', 'pypi.org',
    'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com'
]

# Streaming and entertainment
STREAMING = [
    'netflix.com', 'youtube.com', 'spotify.com', 'twitch.tv', 'hulu.com',
    'disneyplus.com', 'hbomax.com', 'primevideo.com', 'soundcloud.com'
]

# E-commerce
ECOMMERCE = [
    'amazon.com', 'ebay.com', 'walmart.com', 'etsy.com', 'shopify.com',
    'target.com', 'bestbuy.com', 'aliexpress.com', 'alibaba.com'
]

# Email and communication
COMMUNICATION = [
    'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com', 
    'slack.com', 'zoom.us', 'teams.microsoft.com', 'discord.com'
]

# Social media
SOCIAL_MEDIA = [
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'pinterest.com', 'tiktok.com', 'snapchat.com'
]

# CDN and Common Services (appear in many requests)
CDN_SERVICES = [
    'cloudflare.com', 'akamai.com', 'cdn.jsdelivr.net', 'unpkg.com',
    'googleapis.com', 'gstatic.com', 'fbcdn.net', 'twimg.com'
]

# =============================================================================
# USER PROFILES - Each user has different browsing behavior
# =============================================================================

USER_PROFILES = {
    "casual_browser": {
        "name": "Casual Web Browser",
        "domains": COMMON_WEBSITES + NEWS_MEDIA + CDN_SERVICES,
        "query_rate": (0.5, 2.0),  # queries per second (min, max)
        "burst_probability": 0.2,   # chance of burst activity
        "record_types": ['A', 'AAAA'],  # mainly basic lookups
        "query_count_range": (20, 50)  # total queries in session
    },
    "tech_developer": {
        "name": "Software Developer",
        "domains": TECH_SITES + COMMON_WEBSITES + CDN_SERVICES,
        "query_rate": (1.0, 3.0),
        "burst_probability": 0.3,
        "record_types": ['A', 'AAAA', 'TXT', 'MX'],
        "query_count_range": (40, 100)
    },
    "video_streamer": {
        "name": "Video Streamer",
        "domains": STREAMING + CDN_SERVICES,
        "query_rate": (0.3, 1.5),
        "burst_probability": 0.15,
        "record_types": ['A', 'AAAA'],
        "query_count_range": (15, 40)
    },
    "online_shopper": {
        "name": "Online Shopper",
        "domains": ECOMMERCE + COMMON_WEBSITES + CDN_SERVICES,
        "query_rate": (0.8, 2.5),
        "burst_probability": 0.25,
        "record_types": ['A', 'AAAA'],
        "query_count_range": (30, 70)
    },
    "social_media_user": {
        "name": "Social Media User",
        "domains": SOCIAL_MEDIA + CDN_SERVICES + COMMON_WEBSITES,
        "query_rate": (1.5, 4.0),
        "burst_probability": 0.35,
        "record_types": ['A', 'AAAA'],
        "query_count_range": (50, 120)
    },
    "email_heavy_user": {
        "name": "Email Power User",
        "domains": COMMUNICATION + COMMON_WEBSITES,
        "query_rate": (0.6, 2.0),
        "burst_probability": 0.2,
        "record_types": ['A', 'AAAA', 'MX', 'TXT'],
        "query_count_range": (25, 60)
    },
    "news_reader": {
        "name": "News Reader",
        "domains": NEWS_MEDIA + COMMON_WEBSITES + CDN_SERVICES,
        "query_rate": (0.7, 2.2),
        "burst_probability": 0.25,
        "record_types": ['A', 'AAAA'],
        "query_count_range": (30, 80)
    },
    "remote_worker": {
        "name": "Remote Worker",
        "domains": COMMUNICATION + TECH_SITES + COMMON_WEBSITES + CDN_SERVICES,
        "query_rate": (1.2, 3.5),
        "burst_probability": 0.3,
        "record_types": ['A', 'AAAA', 'MX', 'TXT', 'SRV'],
        "query_count_range": (60, 150)
    },
    "mobile_user": {
        "name": "Mobile App User",
        "domains": SOCIAL_MEDIA + STREAMING + CDN_SERVICES + COMMON_WEBSITES,
        "query_rate": (0.8, 2.8),
        "burst_probability": 0.4,
        "record_types": ['A', 'AAAA'],
        "query_count_range": (35, 90)
    },
    "gamer": {
        "name": "Online Gamer",
        "domains": ['steampowered.com', 'epicgames.com', 'ea.com', 'battle.net', 
                   'playstation.com', 'xbox.com'] + STREAMING + CDN_SERVICES,
        "query_rate": (0.5, 1.8),
        "burst_probability": 0.2,
        "record_types": ['A', 'AAAA', 'SRV'],
        "query_count_range": (20, 50)
    },
    "researcher": {
        "name": "Academic Researcher",
        "domains": ['scholar.google.com', 'researchgate.net', 'arxiv.org', 
                   'ieee.org', 'nature.com', 'sciencedirect.com', 'pubmed.gov'] 
                   + COMMON_WEBSITES + TECH_SITES,
        "query_rate": (0.6, 2.0),
        "burst_probability": 0.25,
        "record_types": ['A', 'AAAA', 'TXT'],
        "query_count_range": (25, 70)
    },
    "content_creator": {
        "name": "Content Creator",
        "domains": SOCIAL_MEDIA + STREAMING + ['canva.com', 'adobe.com', 
                   'figma.com', 'vimeo.com'] + CDN_SERVICES,
        "query_rate": (1.0, 3.2),
        "burst_probability": 0.35,
        "record_types": ['A', 'AAAA', 'TXT'],
        "query_count_range": (40, 100)
    }
}

# =============================================================================
# DNS QUERY FUNCTIONS
# =============================================================================

# Map record type names to query type codes
DNS_QTYPE = {
    'A': 1,      # IPv4 address
    'AAAA': 28,  # IPv6 address
    'MX': 15,    # Mail exchange
    'TXT': 16,   # Text record
    'NS': 2,     # Name server
    'CNAME': 5,  # Canonical name
    'SRV': 33,   # Service record
    'SOA': 6     # Start of authority
}

def create_dns_query(domain, query_type='A'):
    """
    Create a DNS query packet for the specified domain and type.
    Returns a bytes object representing the DNS query.
    """
    # Transaction ID (random 2 bytes)
    transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
    
    # Flags: Standard query, recursion desired
    flags = b'\x01\x00'
    
    # Question count: 1
    qdcount = b'\x00\x01'
    
    # Answer, Authority, Additional counts: 0
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    
    # Question section
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'  # End of domain name
    
    # Query type and class
    qtype = DNS_QTYPE.get(query_type, 1).to_bytes(2, 'big')
    qclass = b'\x00\x01'  # IN (Internet)
    
    # Combine all parts
    dns_query = transaction_id + flags + qdcount + ancount + nscount + arcount + question + qtype + qclass
    return dns_query

def send_dns_query(domain, query_type='A', dns_server='8.8.8.8', dns_port=53, timeout=2):
    """
    Send a real DNS query over the network and return response time.
    
    Args:
        domain: Domain name to query
        query_type: Type of DNS record (A, AAAA, MX, etc.)
        dns_server: DNS server to query
        dns_port: DNS port (default 53)
        timeout: Socket timeout in seconds
    
    Returns:
        tuple: (success: bool, response_time: float)
    """
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Create DNS query
        query = create_dns_query(domain, query_type)
        
        # Send query and measure time
        start_time = time.time()
        sock.sendto(query, (dns_server, dns_port))
        
        # Receive response
        response, _ = sock.recvfrom(512)
        response_time = time.time() - start_time
        
        sock.close()
        return True, response_time
        
    except socket.timeout:
        if 'sock' in locals():
            sock.close()
        return False, timeout
    except Exception as e:
        if 'sock' in locals():
            sock.close()
        return False, 0

# =============================================================================
# USER SIMULATION CLASS
# =============================================================================

class SimulatedUser:
    """Simulates a single user generating realistic DNS traffic."""
    
    def __init__(self, user_id, profile_name, duration, dns_server='8.8.8.8'):
        self.user_id = user_id
        self.profile = USER_PROFILES[profile_name]
        self.profile_name = profile_name
        self.duration = duration
        self.dns_server = dns_server
        self.total_queries = 0
        self.successful_queries = 0
        self.start_time = None
        self.active = False
        
    def simulate_activity(self):
        """Main activity loop for this user."""
        self.active = True
        self.start_time = time.time()
        
        print(f"[User {self.user_id}] {self.profile['name']} - Starting activity")
        
        # Determine total queries for this session
        min_queries, max_queries = self.profile['query_count_range']
        target_queries = random.randint(min_queries, max_queries)
        
        while self.active and (time.time() - self.start_time) < self.duration:
            # Check if we've reached target
            if self.total_queries >= target_queries:
                break
                
            # Determine if this is a burst period
            is_burst = random.random() < self.profile['burst_probability']
            
            if is_burst:
                # Burst: Multiple queries in quick succession
                burst_size = random.randint(3, 8)
                for _ in range(burst_size):
                    if self.total_queries >= target_queries:
                        break
                    self._send_query()
                    time.sleep(random.uniform(0.1, 0.5))  # Short delay between burst queries
            else:
                # Normal query
                self._send_query()
                
            # Wait before next query (realistic timing)
            min_rate, max_rate = self.profile['query_rate']
            avg_delay = 1.0 / random.uniform(min_rate, max_rate)
            time.sleep(avg_delay)
        
        elapsed = time.time() - self.start_time
        qps = self.total_queries / elapsed if elapsed > 0 else 0
        success_rate = (self.successful_queries / self.total_queries * 100) if self.total_queries > 0 else 0
        
        print(f"[User {self.user_id}] {self.profile['name']} - Completed")
        print(f"  └─ Queries: {self.total_queries}, Successful: {self.successful_queries} ({success_rate:.1f}%)")
        print(f"  └─ QPS: {qps:.2f}, Duration: {elapsed:.1f}s")
        
    def _send_query(self):
        """Send a single DNS query."""
        domain = random.choice(self.profile['domains'])
        query_type = random.choice(self.profile['record_types'])
        
        self.total_queries += 1
        success, response_time = send_dns_query(domain, query_type, self.dns_server)
        
        if success:
            self.successful_queries += 1
        
        # Optional: Print every Nth query for monitoring
        if self.total_queries % 20 == 0:
            print(f"[User {self.user_id}] Query #{self.total_queries}: {domain} ({query_type}) - " +
                  f"{'OK' if success else 'FAIL'} ({response_time*1000:.1f}ms)")
    
    def stop(self):
        """Stop user activity."""
        self.active = False

# =============================================================================
# MAIN TRAFFIC GENERATOR
# =============================================================================

class BenignTrafficGenerator:
    """Main class to coordinate multiple simulated users."""
    
    def __init__(self, num_users=12, duration=300, dns_server='8.8.8.8'):
        self.num_users = num_users
        self.duration = duration
        self.dns_server = dns_server
        self.users = []
        self.threads = []
        
    def start(self):
        """Start all simulated users."""
        print("=" * 80)
        print("REALISTIC BENIGN DNS TRAFFIC GENERATOR")
        print("=" * 80)
        print(f"\nConfiguration:")
        print(f"  - Number of users: {self.num_users}")
        print(f"  - Duration: {self.duration} seconds")
        print(f"  - DNS Server: {self.dns_server}")
        print(f"  - Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "=" * 80)
        print("STARTING USER SIMULATIONS")
        print("=" * 80 + "\n")
        
        # Create users with different profiles
        profile_names = list(USER_PROFILES.keys())
        
        for i in range(self.num_users):
            profile = profile_names[i % len(profile_names)]
            user = SimulatedUser(i+1, profile, self.duration, self.dns_server)
            self.users.append(user)
            
            # Create and start thread
            thread = threading.Thread(target=user.simulate_activity)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
            
            # Stagger user start times slightly
            time.sleep(random.uniform(0.5, 2.0))
        
        print(f"\nAll {self.num_users} users started!\n")
        
        # Wait for all users to complete
        for thread in self.threads:
            thread.join()
        
        print("\n" + "=" * 80)
        print("TRAFFIC GENERATION COMPLETE")
        print("=" * 80)
        self.print_summary()
        
    def print_summary(self):
        """Print summary statistics."""
        total_queries = sum(user.total_queries for user in self.users)
        total_successful = sum(user.successful_queries for user in self.users)
        
        print(f"\nSummary Statistics:")
        print(f"  - Total Users: {self.num_users}")
        print(f"  - Total Queries: {total_queries}")
        print(f"  - Successful Queries: {total_successful}")
        print(f"  - Success Rate: {(total_successful/total_queries*100):.2f}%" if total_queries > 0 else "N/A")
        print(f"  - Average Queries per User: {total_queries/self.num_users:.1f}")
        
        print("\nPer-User Breakdown:")
        for user in self.users:
            print(f"  User {user.user_id} ({user.profile_name}): " +
                  f"{user.total_queries} queries, {user.successful_queries} successful")

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Generate realistic benign DNS traffic for testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate traffic from 15 users for 5 minutes
  python generate_realistic_benign_traffic.py --users 15 --duration 300
  
  # Use custom DNS server
  python generate_realistic_benign_traffic.py --users 10 --dns 1.1.1.1
  
  # Quick test with 5 users for 1 minute
  python generate_realistic_benign_traffic.py --users 5 --duration 60
        """
    )
    
    parser.add_argument('-u', '--users', type=int, default=12,
                        help='Number of simulated users (default: 12)')
    parser.add_argument('-d', '--duration', type=int, default=300,
                        help='Duration in seconds (default: 300)')
    parser.add_argument('--dns', type=str, default='8.8.8.8',
                        help='DNS server to query (default: 8.8.8.8)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.users < 1:
        print("Error: Number of users must be at least 1")
        sys.exit(1)
    if args.duration < 10:
        print("Error: Duration must be at least 10 seconds")
        sys.exit(1)
    
    # Create and start generator
    generator = BenignTrafficGenerator(
        num_users=args.users,
        duration=args.duration,
        dns_server=args.dns
    )
    
    try:
        generator.start()
    except KeyboardInterrupt:
        print("\n\nTraffic generation interrupted by user.")
        print("Exiting...")
        sys.exit(0)

if __name__ == '__main__':
    main()
