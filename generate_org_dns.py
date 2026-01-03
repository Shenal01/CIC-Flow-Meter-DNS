"""
Organizational DNS Traffic Generator
Simulates a realistic office environment with:
1. Bursty user behavior (page loads = multiple queries)
2. "Think time" (pauses between actions)
3. Background noise (OS updates, telemetry)
4. Varied domain categories (SaaS, Dev, Infra, CDNs)
"""

import dns.resolver
import time
import random
import sys
import threading
from datetime import datetime

# --- Configuration ---
DNS_SERVER = '8.8.8.8'
DURATION_SECONDS = 300  # 5 minutes default
USER_THREADS = 5        # Simulate 5 concurrent users
BACKGROUND_THREADS = 2  # Simulate 2 background system processes

# --- Realistic Domain Categories ---
DOMAINS = {
    'productivity': [
        'outlook.office365.com', 'teams.microsoft.com', 'slack.com', 'zoom.us',
        'salesforce.com', 'atlassian.net', 'docs.google.com', 'drive.google.com',
        'notion.so', 'trello.com', 'asana.com', 'dropbox.com'
    ],
    'developer': [
        'github.com', 'gitlab.com', 'stackoverflow.com', 'pypi.org', 'npmjs.com',
        'docker.io', 'aws.amazon.com', 'console.cloud.google.com', 'azure.microsoft.com',
        'readthedocs.io', 'dev.to', 'hashicorp.com'
    ],
    'social_news': [
        'linkedin.com', 'twitter.com', 'reddit.com', 'techcrunch.com',
        'arstechnica.com', 'wired.com', 'medium.com', 'hackernews.com'
    ],
    'infrastructure': [
        'windowsupdate.com', 'time.windows.com', 'telemetry.microsoft.com',
        'googleapis.com', 'gvt1.com', 'digicert.com', 'ident.me',
        'archive.ubuntu.com', 'security.ubuntu.com', 'ntp.org'
    ],
    'cdn_assets': [
        'amazonaws.com', 'cloudfront.net', 'akamai.net', 'fastly.net',
        'googleusercontent.com', 'fbcdn.net', 'cdn.jsdelivr.net',
        'static.cloudflareinsights.com', 'fonts.googleapis.com'
    ],
    'internal': [
        'printer01.local', 'fileserver.corp', 'wiki.internal', 'auth.internal',
        'jenkins.internal', 'monitoring.internal'
    ]
}

# --- Failures & Noise ---
BAD_DOMAINS = [
    'gogle.com', 'facebok.com', 'test.local', 'slqa.com', 
    'random-string-123.local', 'unknown-host.internal'
]

class TrafficGenerator:
    def __init__(self, dns_server):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dns_server]
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.running = True
        self.stats = {'sent': 0, 'success': 0, 'failed': 0, 'nxdomain': 0}
        self.lock = threading.Lock()

    def _log(self, msg):
        # Thread-safe logging
        print(msg)

    def _resolve(self, domain, qtype='A'):
        try:
            self.resolver.resolve(domain, qtype)
            with self.lock:
                self.stats['sent'] += 1
                self.stats['success'] += 1
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            with self.lock:
                self.stats['sent'] += 1
                self.stats['nxdomain'] += 1
            return False
        except Exception:
            with self.lock:
                self.stats['sent'] += 1
                self.stats['failed'] += 1
            return False

    def simulate_user_browsing(self, user_id):
        """Simulates a human user: Burst -> Think -> Burst"""
        self._log(f"[User-{user_id}] Started browsing session")
        
        while self.running:
            # 1. Pick a primary task (e.g., checking Slack or reading News)
            category = random.choice(['productivity', 'developer', 'social_news'])
            primary_domain = random.choice(DOMAINS[category])
            
            # 2. BURST: Visit main site + 3-8 assets (CDNs, APIs)
            self._log(f"[User-{user_id}] Visiting {primary_domain}...")
            
            # Main Query
            self._resolve(primary_domain, 'A')
            if random.random() < 0.3: self._resolve(primary_domain, 'AAAA')
            
            # Asset Burst (Simulate page loading resources)
            num_assets = random.randint(3, 8)
            for _ in range(num_assets):
                asset = random.choice(DOMAINS['cdn_assets'])
                # Quick micro-sleep between asset loads
                time.sleep(random.uniform(0.05, 0.2))
                self._resolve(asset, 'A')

            # 3. Occasional "Typo" or Internal query
            if random.random() < 0.05:
                bad_domain = random.choice(BAD_DOMAINS + DOMAINS['internal'])
                self._resolve(bad_domain)

            # 4. THINK TIME: Read the page / work
            # Varies from 5s (quick check) to 45s (reading)
            think_time = random.uniform(5, 45)
            # self._log(f"[User-{user_id}] Thinking for {think_time:.1f}s...")
            time.sleep(think_time)

    def simulate_background_system(self, sys_id):
        """Simulates automated background noise (Updates, NTP, Telemetry)"""
        self._log(f"[Sys-{sys_id}] Background service started")
        
        while self.running:
            # System tasks happen less frequently but regularly
            domain = random.choice(DOMAINS['infrastructure'])
            
            # Heavy on AAAA and SRV for infra
            qtype = random.choice(['A', 'AAAA', 'SRV', 'TXT'])
            
            self._resolve(domain, qtype)
            
            # Long sleep (systems poll every 30-180s)
            time.sleep(random.uniform(30, 180))

    def start(self, duration):
        threads = []
        
        # Start User Threads
        for i in range(USER_THREADS):
            t = threading.Thread(target=self.simulate_user_browsing, args=(i+1,))
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(random.uniform(1, 5)) # Stagger start times

        # Start Background Threads
        for i in range(BACKGROUND_THREADS):
            t = threading.Thread(target=self.simulate_background_system, args=(i+1,))
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        print(f"\n[INFO] Simulation running for {duration} seconds with:")
        print(f"       - {USER_THREADS} Active Users (Bursty)")
        print(f"       - {BACKGROUND_THREADS} Background Services (Periodic)")
        print(f"       - Target DNS: {DNS_SERVER}")
        print("-" * 60)

        try:
            while time.time() - start_time < duration:
                time.sleep(5)
                # Print stats every 5s
                elapsed = time.time() - start_time
                with self.lock:
                    s = self.stats
                    rate = s['sent'] / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.0f}s] Sent: {s['sent']} | OK: {s['success']} | NX: {s['nxdomain']} | Rate: {rate:.2f} QPS")
        except KeyboardInterrupt:
            print("\n[STOPPED] Keyboad Interrupt")
        finally:
            self.running = False
            print("\n[INFO] Stopping threads...")
            time.sleep(2) # Give threads time to stop

if __name__ == "__main__":
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
    else:
        duration = 300 # Default 5 mins

    sim = TrafficGenerator(DNS_SERVER)
    sim.start(duration)
