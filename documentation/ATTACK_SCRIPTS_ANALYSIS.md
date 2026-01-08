# DNS Attack Scripts Analysis

## Overview

Your `generate_attack_dns.py` script generates **3 types of DNS attacks** for testing your intrusion detection system. Here's what each does:

---

## Attack Type 1: DNS Query Flood (Water Torture)

**What it does**: Floods DNS server with queries for random non-existent subdomains

**Technical Details**:
- **Rate**: 1000 queries per second (QPS)
- **Query Type**: A records (qtype=1) only
- **Pattern**: Random subdomains like `xyzabc123.nonexistent-test-domain.com`
- **Attack Goal**: Exhaust DNS server resources, fill cache with junk

**Code Location**: [Lines 22-71](file:///c:/Users/shenal/Downloads/reseraach/CIC-Flow-Meter-DNS/generate_attack_dns.py#L22-L71)

**Packet Structure**:
```python
pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(
    rd=1,
    qd=DNSQR(qname=domain, qtype=1)  # A record query
)
```

**Expected Features**:
- ✅ High `dns_queries_per_second` (1000 QPS)
- ✅ High `query_response_ratio` (most queries get NXDOMAIN or no response)
- ❌ `dns_any_query_ratio` = 0 (only A records)
- ❌ `dns_txt_query_ratio` = 0 (only A records)

---

## Attack Type 2: DNS Amplification

**What it does**: Queries for large DNS records to amplify response size

**Technical Details**:
- **Rate**: 100 queries per second
- **Query Types**: ANY (255), TXT (16), MX (15) - randomly selected
- **Domains**: Well-known domains with large DNS records (google.com, facebook.com, etc.)
- **Attack Goal**: Cause DNS server to send large responses (amplification factor)

**Code Location**: [Lines 73-131](file:///c:/Users/shenal/Downloads/reseraach/CIC-Flow-Meter-DNS/generate_attack_dns.py#L73-L131)

**Packet Structure**:
```python
qtype = random.choice([255, 16, 15])  # ANY, TXT, MX
pkt = IP(dst=self.target_dns) / UDP(dport=53) / DNS(
    rd=1,
    qd=DNSQR(qname=domain, qtype=qtype)
)
```

**Expected Features**:
- ✅ `dns_any_query_ratio` ~0.33 (33% of queries)
- ✅ `dns_txt_query_ratio` ~0.33 (33% of queries)  
- ✅ High `dns_amplification_factor` (large responses)
- ✅ Moderate `dns_queries_per_second` (100 QPS)

---

## Attack Type 3: Mixed Attack

**What it does**: Combines flood and amplification (70% flood / 30% amplification)

**Technical Details**:
- **Rate**: 500 queries per second
- **Query Distribution**:
  - 70%: Random subdomains with A record queries (flood)
  - 30%: Real domains with ANY/TXT queries (amplification)
- **Attack Goal**: Multi-vector attack - exhaust resources AND cause amplification

**Code Location**: [Lines 133-188](file:///c:/Users/shenal/Downloads/reseraach/CIC-Flow-Meter-DNS/generate_attack_dns.py#L133-L188)

**Packet Structure**:
```python
if random.random() < 0.7:
    # 70% flood
    domain = f"{subdomain}.attack-test.com"
    qtype = 1  # A record
else:
    # 30% amplification
    domain = random.choice(amp_domains)
    qtype = random.choice([255, 16])  # ANY or TXT
```

**Expected Features**:
- ✅ `dns_any_query_ratio` ~0.15 (15% of total)
- ✅ `dns_txt_query_ratio` ~0.15 (15% of total)
- ✅ High `dns_queries_per_second` (500 QPS)
- ✅ Mixed amplification patterns

---

## 🔴 TTL Violations: **NO**

### Does the script create TTL violations?

**Answer: NO** - The script does **NOT** manipulate IP TTL values.

**Evidence**:
```bash
$ grep -i "ttl" generate_attack_dns.py
# No results found
```

**Why not?**:
- Scapy packets use **default TTL** from the OS
- Windows default: TTL=128
- Linux/WSL default: TTL=64
- No custom `ttl=` parameter in IP layer

**What this means for your tool**:
- Running these attack scripts will **NOT** trigger TTL violations
- `ttl_violation_rate` will remain **0** even with attacks
- To test TTL detection, you need **different test traffic**

---

## Summary Table

| Attack Type | Rate (QPS) | Query Types | ANY Ratio | TXT Ratio | TTL Violations |
|-------------|------------|-------------|-----------|-----------|----------------|
| 1. Flood | 1000 | A only | 0% | 0% | ❌ No |
| 2. Amplification | 100 | ANY/TXT/MX | ~33% | ~33% | ❌ No |
| 3. Mixed | 500 | A + ANY/TXT | ~15% | ~15% | ❌ No |

---

## To Test TTL Violations

You'll need to **manually craft packets** with abnormal TTLs:

```python
# Example: Send DNS query with TTL=1 (violation)
from scapy.all import *

pkt = IP(dst="127.0.0.1", ttl=1) / UDP(dport=53) / DNS(
    rd=1,
    qd=DNSQR(qname="test.com", qtype=1)
)
send(pkt)
```

**Abnormal TTL values to test**:
- `ttl=1` - Very low (suspicious)
- `ttl=10` - Below normal range
- `ttl=42` - Non-standard value
- `ttl=111` - Between standard ranges

**Normal TTL values** (won't trigger violations):
- `ttl=64` - Linux/Unix
- `ttl=128` - Windows  
- `ttl=255` - Network devices

---

## Recommendations

1. **Your current attacks are working correctly** for testing query type ratios
2. **To validate TTL violations**, you need to:
   - Implement the TTL detection feature (as per implementation plan)
   - Create a separate test script that sends packets with abnormal TTLs
   - Verify `ttl_violation_rate` becomes non-zero

3. **Expected behavior with current scripts**:
   - Attack Type 1: `dns_any_query_ratio=0, dns_txt_query_ratio=0` ✅ Correct
   - Attack Type 2: Both ratios ~0.33 ✅ Good for ML training
   - Attack Type 3: Both ratios ~0.15 ✅ Mixed patterns

Want me to proceed with implementing TTL violation detection?
