"""
generate_human_traffic.py — Realistic Human-Like Benign Traffic Generator

Usage:
  python generate_human_traffic.py --mode high   --duration 30
  python generate_human_traffic.py --mode medium --duration 60
  python generate_human_traffic.py --mode low    --duration 120

Modes:
  high   -> Developer/power user: many tabs, streaming, large downloads
  medium -> Casual user: email, news, occasional search
  low    -> Idle PC: background sync, NTP, OS pings

DNS Methods used (mixed randomly):
  Traditional DNS -> UDP/TCP port 53 via socket.gethostbyname
  DoH             -> HTTPS POST to 1.1.1.1 or 8.8.8.8 (port 443)
  DoT             -> TLS socket to 8.8.8.8:853
"""

import argparse
import random
import socket
import ssl
import time
import _thread
import requests
from urllib3.exceptions import InsecureRequestWarning
from dnslib import DNSRecord, QTYPE

# Suppress SSL certificate warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ─── DoH / DoT RESOLVER POOLS ─────────────────────────────────────────────────

DOH_RESOLVERS = [
    "https://1.1.1.1/dns-query",     # Cloudflare
    "https://8.8.8.8/dns-query",     # Google
    "https://9.9.9.9/dns-query",     # Quad9
]

DOT_RESOLVERS = [
    ("8.8.8.8",  853),   # Google
    ("1.1.1.1",  853),   # Cloudflare
    ("9.9.9.9",  853),   # Quad9
]

# ─── SITE POOLS PER BEHAVIOUR ─────────────────────────────────────────────────

HIGH_SITES = [
    "https://www.youtube.com", "https://www.twitch.tv",
    "https://github.com", "https://stackoverflow.com",
    "https://docs.microsoft.com", "https://www.reddit.com",
    "https://news.ycombinator.com", "https://www.medium.com",
    "https://www.cloudflare.com", "https://aws.amazon.com",
]

MEDIUM_SITES = [
    "https://www.google.com", "https://www.bbc.com/news",
    "https://www.wikipedia.org", "https://mail.google.com",
    "https://www.facebook.com", "https://twitter.com",
    "https://www.linkedin.com", "https://www.amazon.com",
    "https://www.cnn.com", "https://weather.com",
]

LOW_SITES = [
    "https://time.windows.com", "https://www.bing.com",
    "https://ocsp.digicert.com", "https://www.microsoft.com",
]

DNS_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "cloudflare.com", "akamai.com", "fastly.net", "windowsupdate.com",
    "ocsp.digicert.com", "apis.google.com", "fonts.googleapis.com",
    "cdn.jsdelivr.net", "ajax.googleapis.com", "s3.amazonaws.com",
]

# ─── INTENSITY PROFILES ────────────────────────────────────────────────────────

PROFILES = {
    "high": {
        "label":          "HIGH (Power User)",
        "sites":          HIGH_SITES,
        "action_delay":   (0.5, 3.0),    # seconds between actions
        "read_pause":     (1.0, 5.0),    # seconds "reading" the page
        "dns_per_action": (3, 8),        # DNS lookups per web request
        "skip_chance":    0.05,          # probability of skipping an action
        "burst_active":   (20, 60),      # seconds of burst activity
        "burst_idle":     (5, 15),       # seconds of idle between bursts
        "concurrency":    3,             # simultaneous request threads
    },
    "medium": {
        "label":          "MEDIUM (Casual User)",
        "sites":          MEDIUM_SITES,
        "action_delay":   (3.0, 10.0),
        "read_pause":     (5.0, 20.0),
        "dns_per_action": (1, 3),
        "skip_chance":    0.15,
        "burst_active":   (30, 90),
        "burst_idle":     (10, 40),
        "concurrency":    1,
    },
    "low": {
        "label":          "LOW (Idle/Background)",
        "sites":          LOW_SITES,
        "action_delay":   (15.0, 60.0),
        "read_pause":     (0.5, 2.0),
        "dns_per_action": (1, 2),
        "skip_chance":    0.4,
        "burst_active":   (10, 30),
        "burst_idle":     (30, 120),
        "concurrency":    1,
    },
}

# ─── HUMAN JITTER ENGINE ──────────────────────────────────────────────────────

def human_sleep(min_s, max_s):
    """Sleep for a random duration with a Gaussian curve (feels natural)."""
    mean = (min_s + max_s) / 2
    std  = (max_s - min_s) / 4
    t    = max(min_s, random.gauss(mean, std))
    time.sleep(t)


def do_traditional_dns(domains, count):
    """UDP/TCP port-53 lookup — OS resolver, no encryption."""
    picked = random.sample(domains, min(count, len(domains)))
    for d in picked:
        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyname(d)
            print(f"  [DNS/trad] {d}")
        except Exception:
            pass


def do_doh_lookup(domains, count):
    """DNS-over-HTTPS — POST binary DNS query to a known DoH resolver."""
    headers = {"Content-Type": "application/dns-message",
               "Accept":       "application/dns-message"}
    picked = random.sample(domains, min(count, len(domains)))
    for d in picked:
        try:
            q      = DNSRecord.question(d, "A")
            data   = q.pack()
            target = random.choice(DOH_RESOLVERS)
            requests.post(target, data=data, headers=headers, timeout=3, verify=False)
            print(f"  [DNS/DoH]  {d} -> {target}")
        except Exception:
            pass


def do_dot_lookup(domains, count):
    """DNS-over-TLS — raw TLS socket to port 853."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    picked = random.sample(domains, min(count, len(domains)))
    for d in picked:
        try:
            q      = DNSRecord.question(d, "A")
            data   = q.pack()
            length = len(data).to_bytes(2, "big")
            ip, port = random.choice(DOT_RESOLVERS)
            with socket.create_connection((ip, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                    tls.send(length + data)
            print(f"  [DNS/DoT]  {d} -> {ip}:853")
        except Exception:
            pass


def do_dns_lookup(domains, count):
    """Randomly pick Traditional / DoH / DoT — like a real device that mixes resolvers."""
    method = random.choices(
        ["traditional", "doh", "dot"],
        weights=[0.50, 0.30, 0.20],   # 50% traditional, 30% DoH, 20% DoT
        k=1
    )[0]
    if method == "traditional":
        do_traditional_dns(domains, count)
    elif method == "doh":
        do_doh_lookup(domains, count)
    else:
        do_dot_lookup(domains, count)


def do_http_get(url, profile):
    """Load a web page like a browser — follow redirects, realistic headers."""
    headers = {
        "User-Agent":      random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 Safari/605.1.15",
        ]),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection":      "keep-alive",
    }
    try:
        r = requests.get(url, headers=headers, timeout=5,
                         allow_redirects=True, verify=False)
        print(f"  [HTTP] {r.status_code} <- {url[:55]}")
    except Exception as e:
        print(f"  [HTTP] SKIP  {url[:55]}  ({type(e).__name__})")


# ─── ACTIVITY LOOPS PER MODE ──────────────────────────────────────────────────

def activity_loop(profile_key, stop_flag):
    p = PROFILES[profile_key]

    while not stop_flag[0]:
        # ── Burst phase ──────────────────────────────────────
        burst_end = time.time() + random.uniform(*p["burst_active"])
        print(f"\n[BURST] Starting {p['label']} burst...")

        while time.time() < burst_end and not stop_flag[0]:
            # Human distraction: randomly skip this action
            if random.random() < p["skip_chance"]:
                time.sleep(random.uniform(0.2, 1.0))
                continue

            url = random.choice(p["sites"])

            # 1. DNS lookups first (like a real browser)
            dns_count = random.randint(*p["dns_per_action"])
            subdomain = f"www.{url.replace('https://','').replace('http://','')}"
            extra_dns  = random.sample(DNS_DOMAINS, min(dns_count, len(DNS_DOMAINS)))
            do_dns_lookup([subdomain] + extra_dns, dns_count)

            # 2. HTTP GET
            do_http_get(url, p)

            # 3. "Reading" pause (human is reading the page)
            human_sleep(*p["read_pause"])

            # 4. Action delay (thinking before next click)
            human_sleep(*p["action_delay"])

        # ── Idle phase ───────────────────────────────────────
        idle_dur = random.uniform(*p["burst_idle"])
        print(f"\n[IDLE]  Resting for {idle_dur:.0f}s...")
        time.sleep(idle_dur)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Human-Like Benign Traffic Generator")
    parser.add_argument("--mode",     choices=["high", "medium", "low"], default="medium",
                        help="Traffic intensity mode")
    parser.add_argument("--duration", type=int, default=30,
                        help="How many minutes to run (default: 30)")
    args = parser.parse_args()

    p = PROFILES[args.mode]
    end_time = time.time() + args.duration * 60
    stop_flag = [False]

    print("=" * 60)
    print(f"  HUMAN-LIKE TRAFFIC GENERATOR")
    print(f"  Mode      : {p['label']}")
    print(f"  Duration  : {args.duration} minutes")
    print("=" * 60)

    # Launch concurrent threads if high mode
    for i in range(p["concurrency"]):
        _thread.start_new_thread(activity_loop, (args.mode, stop_flag))
        time.sleep(random.uniform(0.5, 2.0))  # stagger thread starts

    try:
        while time.time() < end_time:
            time.sleep(5)

        stop_flag[0] = True
        print("\n[DONE] Traffic generation complete.")

    except KeyboardInterrupt:
        stop_flag[0] = True
        print("\n[STOP] Stopped by user.")


if __name__ == "__main__":
    main()
