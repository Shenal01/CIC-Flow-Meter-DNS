# Manual Validation Plan - CIC-Flow-Meter-DNS
## Column-by-Column Verification with tshark & Manual Calculations

---

## Overview

This document provides step-by-step manual validation procedures for **all 41 features** extracted by CIC-Flow-Meter-DNS using:
1. **tshark** - Command-line network protocol analyzer (Wireshark CLI)
2. **Manual calculations** - Excel/calculator-based verification
3. **Wireshark GUI** - Visual verification of complex features

We will validate **both attack and benign traffic** to ensure accuracy across different traffic patterns.

---

## Prerequisites

### Install tshark
```powershell
# Windows (via Chocolatey)
choco install wireshark

# Or download from: https://www.wireshark.org/download.html
# tshark is included with Wireshark installation
```

### Verify Installation
```powershell
tshark --version
```

---

## Test Files to Validate

| File | Type | Description | Validation Focus |
|------|------|-------------|------------------|
| `benign_dns_simple.pcap` | Benign | Single query/response | Basic accuracy |
| `benign_normal_browsing.pcap` | Benign | 107 queries, 5 users | Real-world patterns |
| `attack_dns_amplification.pcap` | Attack | 3000 queries, ANY/TXT | Attack detection |
| `attack_dns_flood.pcap` | Attack | 10000 queries | High volume |

---

## Category 1: DNS Critical Features (10 features)

### Feature 1: `dns_amplification_factor`

**Definition**: Total Response Bytes / Total Query Bytes

**Manual Validation Steps**:

```powershell
# Step 1: Extract DNS queries and responses to CSV
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns" -T fields -e frame.number -e dns.flags.response -e frame.len -E header=y -E separator=, > dns_packets.csv

# Step 2: Open dns_packets.csv in Excel
# Column A: frame.number
# Column B: dns.flags.response (0=query, 1=response)
# Column C: frame.len

# Step 3: Calculate in Excel:
# D2: =IF(B2=0, C2, 0)  -- Query bytes
# E2: =IF(B2=1, C2, 0)  -- Response bytes
# Drag formulas down

# Step 4: Sum totals
# Total Query Bytes = SUM(D:D)
# Total Response Bytes = SUM(E:E)
# Amplification Factor = Total Response Bytes / Total Query Bytes
```

**Alternative: Direct tshark calculation**
```powershell
# Count total bytes in DNS queries
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 0" -T fields -e frame.len | measure-object -Sum

# Count total bytes in DNS responses
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" -T fields -e frame.len | measure-object -Sum

# Calculate: Response Sum / Query Sum
```

**Compare with Tool Output**:
```powershell
# Get tool's value
$csv = Import-Csv validation_output\benign_simple_output.csv
$toolValue = $csv.dns_amplification_factor
Write-Host "Tool: $toolValue"
Write-Host "Manual: [calculated value]"
```

---

### Feature 2: `query_response_ratio`

**Definition**: Number of Query Packets / Number of Response Packets

**Manual Steps**:

```powershell
# Count DNS queries
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 0" | measure-object -Line

# Count DNS responses
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" | measure-object -Line

# Calculate: Query Count / Response Count
```

---

### Feature 3: `dns_any_query_ratio`

**Definition**: ANY Queries / Total Queries

**Manual Steps**:

```powershell
# Count total queries
$totalQueries = (tshark -r test_pcaps\attack_dns_amplification.pcap -Y "dns.flags.response == 0" | measure-object -Line).Lines

# Count ANY queries (query type 255)
$anyQueries = (tshark -r test_pcaps\attack_dns_amplification.pcap -Y "dns.qry.type == 255" | measure-object -Line).Lines

# Calculate ratio
$ratio = $anyQueries / $totalQueries
Write-Host "ANY Query Ratio: $ratio"
```

**Excel Verification**:
```powershell
# Export all DNS queries with query type
tshark -r test_pcaps\attack_dns_amplification.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name -e dns.qry.type -E header=y -E separator=, > query_types.csv

# In Excel:
# Count rows where dns.qry.type = 255
# Divide by total query count
```

---

### Feature 4: `dns_txt_query_ratio`

**Definition**: TXT Queries / Total Queries

**Manual Steps**:

```powershell
# Count TXT queries (query type 16)
$txtQueries = (tshark -r test_pcaps\attack_dns_amplification.pcap -Y "dns.qry.type == 16" | measure-object -Line).Lines

# Calculate ratio
$txtRatio = $txtQueries / $totalQueries
Write-Host "TXT Query Ratio: $txtRatio"
```

---

### Feature 5: `dns_server_fanout`

**Definition**: Number of unique destination IPs contacted (currently placeholder = 0)

**Manual Steps**:

```powershell
# Extract unique destination IPs for DNS traffic
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns" -T fields -e ip.dst | Sort-Object -Unique

# Count unique IPs
$uniqueServers = (tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns" -T fields -e ip.dst | Sort-Object -Unique).Count
Write-Host "Unique DNS Servers: $uniqueServers"
```

**Note**: Currently expected to be 0 (placeholder feature)

---

### Feature 6: `dns_response_inconsistency`

**Definition**: abs(Query Count - Response Count)

**Manual Steps**:

```powershell
$queries = (tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 0" | measure-object -Line).Lines
$responses = (tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" | measure-object -Line).Lines

$inconsistency = [Math]::Abs($queries - $responses)
Write-Host "Response Inconsistency: $inconsistency"
```

---

### Feature 7: `ttl_violation_rate`

**Definition**: Count of packets with non-standard IP TTL values (currently = 0)

**Manual Steps**:

```powershell
# Extract all IP TTL values
tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e ip.ttl > ttl_values.txt

# In Excel, count TTLs that are NOT standard (64, 128, 255)
# Standard OS TTLs: Linux=64, Windows=128, Cisco=255
```

---

### Feature 8: `dns_queries_per_second`

**Definition**: Total Queries / Flow Duration (seconds)

**Manual Steps**:

```powershell
# Get capture duration
tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.time_epoch | 
    Measure-Object -Minimum -Maximum

# Calculate duration in seconds
$firstPacket = [double]"[first timestamp]"
$lastPacket = [double]"[last timestamp]"
$duration = $lastPacket - $firstPacket

# Get query count
$queryCount = (tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 0" | measure-object -Line).Lines

# Calculate QPS
$qps = $queryCount / $duration
Write-Host "Queries Per Second: $qps"
```

---

### Feature 9: `dns_mean_answers_per_query`

**Definition**: Total Answer Count / Response Packet Count

**Manual Steps**:

```powershell
# Export DNS responses with answer count
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" -T fields -e dns.count.answers -E header=y > answer_counts.txt

# In Excel/PowerShell:
# Sum all answer counts
# Divide by number of response packets
```

**Alternative**:
```powershell
$answerCounts = tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" -T fields -e dns.count.answers
$totalAnswers = ($answerCounts | Measure-Object -Sum).Sum
$responseCount = ($answerCounts | Measure-Object).Count
$meanAnswers = $totalAnswers / $responseCount
Write-Host "Mean Answers Per Query: $meanAnswers"
```

---

### Feature 10: `port_53_traffic_ratio`

**Definition**: DNS Traffic Bytes / Total Flow Bytes

**Manual Steps**:

```powershell
# Total bytes in capture
$totalBytes = (tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.len | Measure-Object -Sum).Sum

# DNS bytes (port 53 traffic)
$dnsBytes = (tshark -r test_pcaps\benign_dns_simple.pcap -Y "udp.port == 53" -T fields -e frame.len | Measure-Object -Sum).Sum

# Calculate ratio
$ratio = $dnsBytes / $totalBytes
Write-Host "Port 53 Traffic Ratio: $ratio"
```

---

## Category 2: Flow Rate Features (4 features)

### Feature 11: `flow_bytes_per_sec`

**Definition**: Total Bytes / Duration (seconds)

**Manual Steps**:

```powershell
# Get total bytes
$totalBytes = (tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.len | Measure-Object -Sum).Sum

# Get duration
$times = tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.time_epoch
$firstTime = [double]$times[0]
$lastTime = [double]$times[-1]
$duration = $lastTime - $firstTime

# Calculate
$bytesPerSec = $totalBytes / $duration
Write-Host "Flow Bytes Per Second: $bytesPerSec"
```

---

### Feature 12-14: `flow_packets_per_sec`, `fwd_packets_per_sec`, `bwd_packets_per_sec`

**Manual Steps**:

```powershell
# Total packets
$totalPackets = (tshark -r test_pcaps\benign_dns_simple.pcap | Measure-Object -Line).Lines
$packetsPerSec = $totalPackets / $duration

# Forward packets (from source IP)
$srcIP = "192.168.1.50"  # First packet's source
$fwdPackets = (tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.src == $srcIP" | Measure-Object -Line).Lines
$fwdPacketsPerSec = $fwdPackets / $duration

# Backward packets
$bwdPackets = $totalPackets - $fwdPackets
$bwdPacketsPerSec = $bwdPackets / $duration
```

---

## Category 3: Flow Statistics (5 features)

### Feature 15: `flow_duration`

**Manual Steps**:

```powershell
# Export timestamps
tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.time_epoch > timestamps.txt

# In Excel:
# First timestamp: MIN(A:A)
# Last timestamp: MAX(A:A)
# Duration (ms) = (MAX - MIN) * 1000
```

---

### Features 16-20: Packet/Byte Counts

```powershell
# total_fwd_packets
tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.src == 192.168.1.50" | Measure-Object -Line

# total_bwd_packets
tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.dst == 192.168.1.50" | Measure-Object -Line

# total_fwd_bytes
tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.src == 192.168.1.50" -T fields -e frame.len | Measure-Object -Sum

# total_bwd_bytes
tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.dst == 192.168.1.50" -T fields -e frame.len | Measure-Object -Sum
```

---

## Category 4: DNS Aggregates (3 features)

### Features 21-23: DNS Totals

```powershell
# dns_total_queries
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 0" | Measure-Object -Line

# dns_total_responses
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" | Measure-Object -Line

# dns_response_bytes
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns.flags.response == 1" -T fields -e frame.len | Measure-Object -Sum
```

---

## Category 5: Timing Features (6 features)

### Features 24-29: Inter-Arrival Times (IAT)

**Manual Steps**:

```powershell
# Export all timestamps
tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.time_epoch > all_timestamps.csv

# In Excel:
# Column A: Timestamp
# Column B: =A3-A2 (IAT in seconds, start from row 2)
# Column C: =B2*1000 (IAT in milliseconds)

# Calculate statistics:
# flow_iat_mean = AVERAGE(C:C)
# flow_iat_std = STDEV(C:C)
# flow_iat_min = MIN(C:C)
# flow_iat_max = MAX(C:C)
```

**Forward/Backward IAT**:
```powershell
# Export with IP source
tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.time_epoch -e ip.src -E separator=, > timestamps_with_src.csv

# In Excel:
# Filter rows where ip.src = source IP
# Calculate IAT for forward packets only
# Repeat for backward packets
```

---

## Category 6: Packet Size Features (5 features)

### Features 30-34: Packet Lengths

```powershell
# Export all packet lengths
tshark -r test_pcaps\benign_dns_simple.pcap -T fields -e frame.len > packet_sizes.txt

# In Excel:
# average_packet_size = AVERAGE(A:A)
# packet_size_std = STDEV(A:A)  [or STDEV.S for sample std dev]
# flow_length_min = MIN(A:A)
# flow_length_max = MAX(A:A)

# Forward packet mean
tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.src == 192.168.1.50" -T fields -e frame.len > fwd_sizes.txt
# fwd_packet_length_mean = AVERAGE(fwd_sizes)

# Backward packet mean
tshark -r test_pcaps\benign_dns_simple.pcap -Y "ip.dst == 192.168.1.50" -T fields -e frame.len > bwd_sizes.txt
# bwd_packet_length_mean = AVERAGE(bwd_sizes)
```

---

## Category 7: Advanced Features (2 features)

### Feature 35: `response_time_variance`

**Manual Steps**:

```powershell
# Export DNS transactions with timestamps
tshark -r test_pcaps\benign_dns_simple.pcap -Y "dns" -T fields -e frame.time_epoch -e dns.id -e dns.flags.response -E separator=, > dns_transactions.csv

# In Excel:
# Match queries to responses by dns.id
# Calculate response time = response_timestamp - query_timestamp
# response_time_variance = VAR(response_times)
```

---

## Automated Validation Script

Create `validate_with_tshark.ps1`:

```powershell
# PowerShell script for automated tshark validation

param(
    [string]$PcapFile,
    [string]$CsvFile
)

Write-Host "=" * 70
Write-Host "TSHARK VALIDATION - $PcapFile"
Write-Host "=" * 70

# Category 1: DNS Critical Features
Write-Host "`n[DNS Critical Features]"

# 1. Amplification Factor
$queryBytes = (tshark -r $PcapFile -Y "dns.flags.response == 0" -T fields -e frame.len | Measure-Object -Sum).Sum
$responseBytes = (tshark -r $PcapFile -Y "dns.flags.response == 1" -T fields -e frame.len | Measure-Object -Sum).Sum
$ampFactor = if ($queryBytes -gt 0) { $responseBytes / $queryBytes } else { 0 }
Write-Host "  dns_amplification_factor: $ampFactor"

# 2. Query/Response Ratio
$queryCount = (tshark -r $PcapFile -Y "dns.flags.response == 0" | Measure-Object -Line).Lines
$responseCount = (tshark -r $PcapFile -Y "dns.flags.response == 1" | Measure-Object -Line).Lines
$qrRatio = if ($responseCount -gt 0) { $queryCount / $responseCount } else { $queryCount }
Write-Host "  query_response_ratio: $qrRatio"

# 3. ANY Query Ratio
$anyCount = (tshark -r $PcapFile -Y "dns.qry.type == 255" | Measure-Object -Line).Lines
$anyRatio = if ($queryCount -gt 0) { $anyCount / $queryCount } else { 0 }
Write-Host "  dns_any_query_ratio: $anyRatio"

# 4. TXT Query Ratio
$txtCount = (tshark -r $PcapFile -Y "dns.qry.type == 16" | Measure-Object -Line).Lines
$txtRatio = if ($queryCount -gt 0) { $txtCount / $queryCount } else { 0 }
Write-Host "  dns_txt_query_ratio: $txtRatio"

# Continue for all 41 features...

Write-Host "`n`nCompare with tool output:"
$csv = Import-Csv $CsvFile
Write-Host "Tool dns_amplification_factor: $($csv.dns_amplification_factor)"
Write-Host "Manual calculation: $ampFactor"
Write-Host "Match: $(if ([Math]::Abs($csv.dns_amplification_factor - $ampFactor) -lt 0.01) { 'YES' } else { 'NO' })"
```

---

## Execution Plan

### Phase 1: Benign Simple PCAP (Baseline)
**File**: `benign_dns_simple.pcap` (1 query, 1 response)

1. Run all tshark commands manually
2. Record values in Excel spreadsheet
3. Compare with tool output CSV
4. Document any discrepancies

**Expected Time**: 30-45 minutes

---

### Phase 2: Benign Normal Browsing (Realistic)
**File**: `benign_normal_browsing.pcap` (107 queries, multi-user)

1. Run automated PowerShell script
2. Manual spot-check of 5-10 features
3. Excel analysis for timing/statistical features

**Expected Time**: 20-30 minutes

---

### Phase 3: Attack Amplification (Critical)
**File**: `attack_dns_amplification.pcap` (3000 queries, ANY/TXT)

1. Focus on DNS attack features (ANY ratio, TXT ratio, QPS)
2. Verify high amplification factor
3. Check query/response inconsistency

**Expected Time**: 30 minutes

---

### Phase 4: Attack Flood (Volume)
**File**: `attack_dns_flood.pcap` (10000 queries)

1. Verify high QPS calculation
2. Check low response ratio
3. Validate timing under high volume

**Expected Time**: 30 minutes

---

## Deliverables

1. **Excel Validation Workbook** (`validation_results.xlsx`)
   - Sheet 1: Benign Simple - All 41 features
   - Sheet 2: Benign Browsing - Spot checks
   - Sheet 3: Attack Amplification - DNS features
   - Sheet 4: Attack Flood - Volume features
   - Sheet 5: Summary - Pass/Fail by category

2. **Column-by-Column Report** (Markdown)
   - Each feature with: tshark command, manual result, tool result, match status

3. **Automated Scripts**
   - `validate_with_tshark.ps1` - PowerShell automation
   - `compare_results.py` - Python comparison tool

---

## Success Criteria

✅ **Pass**: Manual calculation matches tool output within 0.1% for counts, 1% for ratios  
⚠️ **Review**: Difference between 1-5%  
❌ **Fail**: Difference >5% or logic error

**Target**: >95% of features pass validation across all 4 test files
