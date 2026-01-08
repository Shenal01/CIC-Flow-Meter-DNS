# Enhanced DNS Traffic Generator - Usage Guide

## Overview

`generate_enhanced_dns.py` creates realistic DNS traffic patterns matching training data characteristics. Use this to generate live traffic for capture and testing.

## Key Improvements Over generate_org_dns.py

| Feature | Original | Enhanced |
|---------|----------|----------|
| Query Rate | ~1 QPS | ~15 QPS (configurable) |
| Query Types | A, AAAA only | A, AAAA, MX, TXT, NS, SRV, CNAME |
| Pattern | Single-threaded | Multi-threaded bursts + sustained |
| Domain Variety | Basic | Popular sites, CDNs, email, subdomains |
| Response Size | Small | Varied (MX, TXT create larger responses) |
| Amplification | Low (~1x) | Higher (~5-20x with MX/TXT queries) |

## Usage

### Basic Usage (Default: 5 minutes at 15 QPS)
```bash
python generate_enhanced_dns.py
```

### Custom Duration (e.g., 10 minutes)
```bash
python generate_enhanced_dns.py 600
```

### Custom Duration and Query Rate (e.g., 5 min at 20 QPS)
```bash
python generate_enhanced_dns.py 300 20
```

## Complete Workflow

### Step 1: Start DNS Traffic Generator
```bash
# In Terminal 1: Generate DNS traffic
python generate_enhanced_dns.py 300 15
```

### Step 2: Capture with CIC-Flow-Meter Tool
```bash
# In Terminal 2: Capture the traffic
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target

java -jar net-traffic-analysis-1.0-SNAPSHOT.jar \
  -i "\Device\NPF_{E608A5BF-65D8-49D7-8BE7-A7BA63E06B86}" \
  -o "C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\enhanced_benign_capture.csv"
```

**Note:** Replace the interface name with your actual network interface. Find it with `ipconfig /all`

### Step 3: Test with Model
```bash
# Update test_lightgbm_model.py to include your captured file
# Then run:
python test_lightgbm_model.py
```

## Expected Results

Based on training data characteristics, this generator should produce:

- **Protocol**: 85-90% UDP (DNS), 10-15% TCP
- **DNS Amplification**: Higher than original (~5-20x vs ~1x)
- **Query/Response Ratio**: More balanced (~0.3-0.7 vs 0.0)
- **Queries per Second**: ~15 (vs ~1)
- **Flow Bytes**: Higher due to MX/TXT responses

## Comparison with Previous Approaches

| Approach | Predicted Benign | Status |
|----------|------------------|--------|
| Training Data | 99.4% | ✓ Perfect (baseline) |
| CSV Generator | 5.2% | ⚠️ Partial improvement |
| Original Live | 0.0% | ✗ Failed |
| **Enhanced Live** | **TBD** | **Test after capture** |

## Tips for Best Results

1. **Run for Longer**: 5-10 minutes minimum for sufficient flows
2. **Higher QPS**: Try 20-25 QPS for more activity
3. **Monitor Capture**: Ensure CIC-Flow-Meter is capturing packets
4. **Check CSV**: Verify CSV has proper column alignment
5. **Compare Stats**: Check if features match training distribution

## Troubleshooting

**Low Query Rate?**
- Increase threads in code or raise QPS parameter
- Check DNS server response time

**No Traffic Captured?**
- Verify network interface name
- Ensure firewall allows DNS traffic
- Check DNS server is reachable

**Still Predicted as Attack?**
- Live traffic may still differ from training patterns
- Consider retraining model with live-captured samples
- Use training data extracts for validation

## Example Session

```bash
# Terminal 1: Generate traffic
PS C:\...\CIC-Flow-Meter-DNS> python generate_enhanced_dns.py 300 20

[START] 2026-01-05 00:20:00
[INFO] Generating DNS traffic for 300 seconds at ~20 QPS
[INFO] Capture this traffic with your CIC-Flow-Meter tool

================================================================================
ENHANCED DNS TRAFFIC GENERATOR
================================================================================

Target: 20 queries/second
Duration: 300 seconds
DNS Server: 8.8.8.8
Threads: 5 (3 burst + 2 sustained)
================================================================================

[   5s] Sent:    102 | OK:    98 | NX:    2 | Actual QPS:  20.40
[  10s] Sent:    205 | OK:   198 | NX:    4 | Actual QPS:  20.50
...
```

```bash
# Terminal 2: Capture traffic
PS C:\...\target> java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "YOUR_INTERFACE" -o "enhanced_capture.csv"
```

Then test with your model!
