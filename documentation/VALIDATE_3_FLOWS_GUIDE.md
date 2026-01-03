# How to Run the 3-Flow Validation Script

## Quick Start

```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS
.\validate_3_flows.ps1
```

## What It Does

1. **Selects 3 random flows** from your CSV:
   - **TOP section**: Random flow from first 1/3 of CSV
   - **MIDDLE section**: Random flow from middle 1/3 of CSV
   - **BOTTOM section**: Random flow from last 1/3 of CSV

2. **For each flow, validates ALL columns**:
   - Identity (src_ip, dst_ip, src_port, dst_port, protocol)
   - Packet counts (total_fwd_packets, total_bwd_packets)
   - Byte counts (total_fwd_bytes, total_bwd_bytes)
   - Flow duration
   - **Flow length min/max [NEW]**
   - **Flow IAT min/max [NEW]**
   - Flow length mean/std
   - Flow IAT mean/std
   - Packet length means (fwd/bwd)
   - Flow rates (bytes/sec, packets/sec)
   - DNS queries/responses
   - DNS amplification factor
   - **DNS mean answers per query [NEW]**
   - QPS (queries per second)
   - Query/response ratio
   - All other columns

3. **Tests in order**: TOP → MIDDLE → BOTTOM

4. **Shows PASS/FAIL** for each column of each flow

## Expected Output

```
================================================================================
COMPREHENSIVE 3-FLOW VALIDATION - ALL COLUMNS
================================================================================

[INFO] Selected flows for validation:
  TOP section: Row #42 - 192.168.137.72:49153 -> 192.168.137.1:53
  MIDDLE section: Row #38788 - 192.168.137.100:54321 -> 192.168.137.1:53
  BOTTOM section: Row #77001 - 192.168.137.200:12345 -> 192.168.137.1:53

================================================================================
VALIDATING FLOW: TOP (Row #42)
================================================================================

[FLOW IDENTITY]
  src_ip: 192.168.137.72
  dst_ip: 192.168.137.1
  src_port: 49153
  dst_port: 53
  protocol: UDP

[1] PACKET COUNTS
  total_fwd_packets: Tool=7, tshark=7 ✓
  total_bwd_packets: Tool=6, tshark=6 ✓

[2] BYTE COUNTS
  total_fwd_bytes: Tool=511, tshark=511 ✓
  total_bwd_bytes: Tool=726, tshark=726 ✓

[4] FLOW LENGTH STATISTICS [NEW FEATURES]
  flow_length_min: Tool=73, tshark=73 ✓
  flow_length_max: Tool=121, tshark=121 ✓
  average_packet_size: Tool=95.1538, tshark=95.1538 ✓

[5] FLOW IAT STATISTICS [NEW FEATURES]
  flow_iat_min: Tool=2.0, tshark=2.0 ✓
  flow_iat_max: Tool=108309.0, tshark=108309.0 ✓
  flow_iat_mean: Tool=11938.0, tshark=11938.0 ✓

[8] DNS FEATURES
  dns_total_queries: Tool=7, tshark=7 ✓
  dns_total_responses: Tool=6, tshark=6 ✓
  dns_amplification_factor: Tool=1.4207, tshark=1.4207 ✓
  dns_mean_answers_per_query [NEW]: Tool=3.0, tshark=3.0 ✓
  dns_queries_per_second: Tool=0.0489, tshark=0.0489 ✓

... (validation continues for MIDDLE and BOTTOM flows) ...

================================================================================
FINAL SUMMARY - ALL 3 FLOWS
================================================================================

[RESULTS BY FLOW]

TOP Flow (Row #42):
  PASS: 35/35
  FAIL: 0/35
  Success Rate: 100.0%

MIDDLE Flow (Row #38788):
  PASS: 35/35
  FAIL: 0/35
  Success Rate: 100.0%

BOTTOM Flow (Row #77001):
  PASS: 35/35
  FAIL: 0/35
  Success Rate: 100.0%

[OVERALL STATISTICS]
  Total Checks: 105
  Total PASS: 105
  Total FAIL: 0
  Overall Success Rate: 100.0%

[SUCCESS] ALL VALIDATIONS PASSED!

Detailed results saved to: validation_results_3flows.csv
```

## Output Files

After running, you'll get:
- **`validation_results_3flows.csv`** - Detailed results for all validations

## Key Features Tested

### New Features (Main Focus)
1. ✅ `flow_length_min` - Minimum packet size
2. ✅ `flow_length_max` - Maximum packet size
3. ✅ `flow_iat_min` - Minimum inter-arrival time
4. ✅ `flow_iat_max` - Maximum inter-arrival time
5. ✅ `dns_mean_answers_per_query` - Average DNS answers

### Existing Features
- All packet counts and byte counts
- Flow duration and rates
- DNS queries, responses, amplification factor
- QPS and all other columns

## Customization

To use different files:
```powershell
.\validate_3_flows.ps1 -PcapFile "path\to\your.pcap" -CsvFile "path\to\your.csv"
```
