# Realistic Benign DNS Traffic Generator

## Overview

This script generates **realistic benign DNS traffic** by simulating multiple users with different browsing behaviors. It sends **actual DNS queries over the network** that can be captured by your CIC-Flow-Meter-DNS tool for testing and model validation.

## Features

✅ **12 Different User Profiles** - Each with unique browsing patterns  
✅ **Real Network Traffic** - Sends actual DNS queries via UDP/53  
✅ **Realistic Timing** - Mimics human behavior with varied query rates  
✅ **Multiple Record Types** - A, AAAA, MX, TXT, SRV, NS records  
✅ **Burst Patterns** - Simulates realistic browsing bursts  
✅ **Threading** - Multiple users run concurrently  
✅ **Configurable** - Adjust users, duration, and DNS server  

## User Profiles

The script includes 12 distinct user personas:

| Profile | Behavior | Queries/sec | Domains |
|---------|----------|-------------|---------|
| **Casual Browser** | General web browsing | 0.5-2.0 | News, social media, common sites |
| **Tech Developer** | Software development | 1.0-3.0 | GitHub, Stack Overflow, cloud services |
| **Video Streamer** | Streaming content | 0.3-1.5 | Netflix, YouTube, Spotify |
| **Online Shopper** | E-commerce | 0.8-2.5 | Amazon, eBay, shopping sites |
| **Social Media User** | Social networking | 1.5-4.0 | Facebook, Twitter, Instagram |
| **Email User** | Heavy email usage | 0.6-2.0 | Gmail, Outlook, communication tools |
| **News Reader** | News consumption | 0.7-2.2 | CNN, BBC, news sites |
| **Remote Worker** | Work from home | 1.2-3.5 | Slack, Zoom, cloud services |
| **Mobile User** | Mobile apps | 0.8-2.8 | Social media, apps, CDNs |
| **Gamer** | Online gaming | 0.5-1.8 | Steam, Epic, gaming platforms |
| **Researcher** | Academic research | 0.6-2.0 | Scholar, arXiv, academic sites |
| **Content Creator** | Content creation | 1.0-3.2 | YouTube, social media, design tools |

## Installation

No additional packages required! Uses only Python standard library:
- `socket` - for DNS queries
- `threading` - for concurrent users
- `random`, `time`, `argparse` - standard utilities

```bash
# Just run it with Python 3.6+
python generate_realistic_benign_traffic.py
```

## Usage

### Basic Usage

```bash
# Default: 12 users for 5 minutes using Google DNS
python generate_realistic_benign_traffic.py
```

### Custom Configuration

```bash
# 15 users for 10 minutes
python generate_realistic_benign_traffic.py --users 15 --duration 600

# Use Cloudflare DNS
python generate_realistic_benign_traffic.py --dns 1.1.1.1

# Quick test: 5 users for 1 minute
python generate_realistic_benign_traffic.py --users 5 --duration 60
```

### Command Line Arguments

```
-u, --users NUM       Number of simulated users (default: 12)
-d, --duration SEC    Duration in seconds (default: 300)
--dns SERVER          DNS server to query (default: 8.8.8.8)
```

## Capturing Traffic with CIC-Flow-Meter-DNS

### Step 1: Start CIC-Flow-Meter-DNS

```bash
# Start your CIC-Flow-Meter-DNS tool on the network interface
# Adjust interface name as needed (e.g. Wi-Fi, Ethernet, eth0, wlan0)
./bin/cfm <INTERFACE_NAME> output_benign.csv
# or
java -jar cfm.jar <INTERFACE_NAME> output_benign.csv
```

### Step 2: Run Traffic Generator

In a **separate terminal**, run the traffic generator:

```bash
python generate_realistic_benign_traffic.py --users 15 --duration 300
```

### Step 3: Stop and Analyze

After the duration completes:
1. Traffic generator will automatically stop
2. Press `Ctrl+C` in the CIC-Flow-Meter-DNS terminal
3. Check `output_benign.csv` for captured flows

## Example Output

```
================================================================================
REALISTIC BENIGN DNS TRAFFIC GENERATOR
================================================================================

Configuration:
  - Number of users: 12
  - Duration: 300 seconds
  - DNS Server: 8.8.8.8
  - Start Time: 2026-01-05 07:45:30

================================================================================
STARTING USER SIMULATIONS
================================================================================

[User 1] Casual Web Browser - Starting activity
[User 2] Software Developer - Starting activity
[User 3] Video Streamer - Starting activity
...

[User 1] Query #20: google.com (A) - OK (15.3ms)
[User 2] Query #40: github.com (AAAA) - OK (22.1ms)
...

[User 1] Casual Web Browser - Completed
  └─ Queries: 45, Successful: 44 (97.8%)
  └─ QPS: 0.90, Duration: 50.2s

================================================================================
TRAFFIC GENERATION COMPLETE
================================================================================

Summary Statistics:
  - Total Users: 12
  - Total Queries: 683
  - Successful Queries: 675
  - Success Rate: 98.83%
  - Average Queries per User: 56.9
```

## Traffic Characteristics

The generated traffic has realistic benign characteristics:

### DNS Features (matching training data)
- **Queries per second**: 0.5 - 4.0 (varies by user)
- **Query-Response Ratio**: ~1.0 (normal behavior)
- **Amplification Factor**: Low (typical benign values)
- **Record Types**: Mix of A, AAAA, MX, TXT, SRV
- **Flow Duration**: Varies naturally
- **Burst Patterns**: Occasional bursts mimicking page loads

### Network Patterns
- UDP protocol (port 53)
- Realistic inter-arrival times
- Varied flow durations
- Natural packet size distribution
- Proper query-response patterns

## Testing Your ML Model

This script is perfect for:

1. **Baseline Testing** - Verify model doesn't misclassify benign traffic
2. **False Positive Analysis** - Check for false attack detections
3. **Feature Validation** - Ensure features are correctly extracted
4. **Real-World Simulation** - Test with realistic traffic patterns

### Testing Workflow

```bash
# 1. Generate benign traffic and capture
python generate_realistic_benign_traffic.py --users 20 --duration 600

# 2. Test with your saved model
python test_saved_model.py  # Should classify as BENIGN

# 3. Check accuracy, recall, precision for benign class
```

## Customization

### Adding Custom Domains

Edit the domain lists in the script:

```python
CUSTOM_DOMAINS = [
    'mycompany.com',
    'internalapp.local',
    'custom-service.io'
]

# Add to a user profile
USER_PROFILES["custom_worker"]["domains"] = CUSTOM_DOMAINS + COMMON_WEBSITES
```

### Creating New User Profiles

```python
USER_PROFILES["my_profile"] = {
    "name": "My Custom Profile",
    "domains": CUSTOM_DOMAINS,
    "query_rate": (1.0, 3.0),  # QPS range
    "burst_probability": 0.3,
    "record_types": ['A', 'AAAA'],
    "query_count_range": (50, 150)
}
```

## Troubleshooting

### No DNS responses

```bash
# Check DNS server is reachable
ping 8.8.8.8

# Try different DNS server
python generate_realistic_benign_traffic.py --dns 1.1.1.1
```

### Permission errors (Linux/Mac)

```bash
# May need elevated privileges for raw sockets
sudo python generate_realistic_benign_traffic.py
```

### Firewall blocking

- Ensure outbound UDP port 53 is allowed
- Check firewall rules don't block DNS

## Important Notes

⚠️ **Network Usage**: This script sends real DNS queries over your network  
⚠️ **DNS Server Load**: Use responsibly, don't overload public DNS servers  
⚠️ **Capture Interface**: Make sure CIC-Flow-Meter-DNS is on the right interface  
✅ **Labeled Data**: All traffic from this script should be labeled as **BENIGN (0)**  

## Integration with Your Pipeline

```bash
# Full workflow
# Terminal 1: Start capture
./bin/cfm eth0 benign_traffic_$(date +%Y%m%d_%H%M%S).csv

# Terminal 2: Generate traffic
python generate_realistic_benign_traffic.py --users 15 --duration 300

# Terminal 3 (after completion): Test model
python test_saved_model.py --test-data benign_traffic_20260105_074530.csv
```

## See Also

- `test_saved_model.py` - Test models with captured data
- `generate_attack_dns.py` - Generate attack traffic
- `detect_dns_abuse_enhanced.py` - Real-time detection

---

**Created by**: Cybersecurity Data Science Team  
**Component**: AI/ML Detection of DNS Abuse and Infrastructure Attacks  
**Last Updated**: 2026-01-05
