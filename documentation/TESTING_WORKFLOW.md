# Complete Testing Workflow - Step by Step

This guide walks you through the complete process of generating traffic and testing your model.

---

## Prerequisites

### Install Required Python Packages

```powershell
pip install dnspython scapy
```

> **Note**: `scapy` requires Npcap on Windows (you likely already have it)

---

## Workflow 1: Test with Normal Traffic

### Step 1: Start Traffic Capture

Open **PowerShell Terminal 1** (in project directory):
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\test_normal.csv"
```

*Wait for "Listening on interface..." message*

### Step 2: Generate Normal Traffic

Open **PowerShell Terminal 2**:
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS
python generate_normal_dns.py 50 60
# Args: 50 QPS, 60 seconds duration
```

*Wait for completion (~60 seconds)*

### Step 3: Stop Capture

In **Terminal 1**, press `Ctrl+C`

### Step 4: Fix and Test

In **Terminal 2**:
```powershell
# Update fix script to point to new file
# Edit final_fix_csv.py line 9-10:
# input_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\test_normal.csv'
# output_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\test_normal_FIXED.csv'

python final_fix_csv.py

# Update test script
# Edit test_saved_model.py line 31:
# TEST_DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\test_normal_FIXED.csv'

python test_saved_model.py
```

### Expected Result:
```
BENIGN predictions: 70-90%
ATTACK predictions: 10-30%
```

---

## Workflow 2: Test with Attack Traffic

### Step 1: Start Traffic Capture

**PowerShell Terminal 1** (Admin):
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\test_attack.csv"
```

### Step 2: Generate Attack Traffic

**PowerShell Terminal 2** (Run as Administrator - REQUIRED):
```powershell
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS
python generate_attack_dns.py
```

Follow prompts:
- Target DNS: `127.0.0.1` (or your router IP)
- Attack type: `1` (DNS Flood)
- Duration: `30` seconds

*Wait for attack to complete*

### Step 3: Stop Capture & Test

**Terminal 1**: Press `Ctrl+C`

**Terminal 2**:
```powershell
# Update paths in scripts as before
python final_fix_csv.py
python test_saved_model.py
```

### Expected Result:
```
BENIGN predictions: 5-20%
ATTACK predictions: 80-95%
```

---

## Workflow 3: Mixed Testing (Recommended)

Test both scenarios back-to-back to compare:

### Round 1: Normal (60 seconds)
```powershell
# Terminal 1
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "test_normal.csv"

# Terminal 2
python generate_normal_dns.py 50 60
# Stop capture, fix CSV, test
```

### Round 2: Attack (30 seconds)
```powershell
# Terminal 1
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "test_attack.csv"

# Terminal 2 (AS ADMIN)
python generate_attack_dns.py
# Choose attack type 1, duration 30
# Stop capture, fix CSV, test
```

### Compare Results

| Scenario | BENIGN % | ATTACK % | Interpretation |
|----------|----------|----------|----------------|
| Normal traffic | 70-90% | 10-30% | ✅ Model correctly identifies benign |
| Attack traffic | 5-20% | 80-95% | ✅ ModelDetects attacks |
| Mixed results | - | - | ⚠️ Model confused or threshold issue |

---

## Troubleshooting

### Issue: "Permission denied" in generate_attack_dns.py

**Solution**: Run PowerShell as Administrator
```powershell
# Right-click PowerShell → "Run as Administrator"
```

### Issue: No traffic captured

**Solutions**:
1. Check interface name: `Get-NetAdapter` in PowerShell
2. Verify DNS traffic is actually being sent
3. Use Wireshark to confirm packets exist

### Issue: Attack generator doesn't send packets

**Check**:
- Npcap is installed
- Running as Administrator
- Firewall not blocking scapy
- Target DNS IP is reachable

### Issue: Model predicts everything as BENIGN even for attacks

**Possible causes**:
1. CSV not fixed (trailing commas)
2. Attack didn't generate enough volume
3. Increase attack rate: edit `generate_attack_dns.py`

### Issue: Model predicts everything as ATTACK even for normal

**Possible causes**:
1. QPS too high (try 20-30 instead of 50)
2. DNS server flagging queries as suspicious
3. Model threshold too low

---

## Quick Commands Reference

### Normal Traffic Generation
```powershell
# Low rate (definitely benign)
python generate_normal_dns.py 10 60

# Medium rate (normal browsing)
python generate_normal_dns.py 50 60

# High rate (heavy usage)
python generate_normal_dns.py 150 60
```

### Attack Traffic Generation
```powershell
# Interactive (recommended)
python generate_attack_dns.py

# Or edit script for automation
```

### Complete Test Cycle
```powershell
# 1. Capture
java -jar target\net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o "test.csv"

# 2. Generate (in another terminal)
python generate_normal_dns.py 50 60

# 3. Stop capture (Ctrl+C), then:
python final_fix_csv.py  # Edit paths first!
python test_saved_model.py  # Edit paths first!
```

---

## Advanced: Automated Testing Script

Create `run_test.ps1`:
```powershell
# Automated testing script
param(
    [string]$Type = "normal"  # or "attack"
)

$OutputFile = "test_$Type.csv"

# Start capture in background
Start-Job -Name Capture -ScriptBlock {
    java -jar target\net-traffic-analysis-1.0-SNAPSHOT.jar -i "Wi-Fi" -o $args[0]
} -ArgumentList $OutputFile

Start-Sleep -Seconds 5

# Generate traffic
if ($Type -eq "normal") {
    python generate_normal_dns.py 50 60
} else {
    # Attack requires admin, run interactively
    Write-Host "Run generate_attack_dns.py manually in admin shell"
}

# Stop capture
Stop-Job -Name Capture
Remove-Job -Name Capture

# Fix and test
python final_fix_csv.py
python test_saved_model.py
```

---

## Safety Reminders

⚠️ **IMPORTANT**:
- Only test on your own network or with permission
- Don't target public DNS servers with attacks (8.8.8.8, 1.1.1.1)
- Use `127.0.0.1` or local DNS for testing
- Check that attacks comply with your organization's security policies

✅ **Best Practice**: Set up a local DNS server (dnsmasq) for isolated testing

---

**You're ready to test your model with controlled traffic!**
