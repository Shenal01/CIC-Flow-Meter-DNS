# Enhanced DNS Detection - Quick Reference

## Quick Start

### Detect from Google Sheets (Live Traffic)
```bash
python detect_dns_abuse_enhanced.py \
  --sheet YOUR_SPREADSHEET_ID \
  --credentials credentials.json
```

**Output:** CSV + New Google Sheet with ID displayed

### Detect from CSV File
```bash
python detect_dns_abuse_enhanced.py --csv traffic.csv
```

**Output:** CSV file with all columns + analysis

---

## What You Get

### Output Columns

**All Original Columns Preserved:**
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- All flow features (unchanged)

**7 New Analysis Columns:**
1. `timestamp_range` - Capture time window
2. `prediction` - 0=Benign, 1=Attack
3. `prediction_label` - BENIGN or ATTACK
4. `confidence_benign` - Benign probability (0-1)
5. `confidence_attack` - Attack probability (0-1)
6. `confidence_score` - Maximum confidence
7. `risk_level` - CRITICAL/HIGH/MEDIUM/LOW

---

## Risk Levels

| Level | Confidence | Action |
|-------|------------|--------|
| **CRITICAL** | ≥ 90% | Immediate response |
| **HIGH** | 80-89% | Priority investigation |
| **MEDIUM** | 60-79% | Review recommended |
| **LOW** | < 60% | Monitor |

---

## Common Commands

### Limit Rows (Testing)
```bash
python detect_dns_abuse_enhanced.py --csv data.csv --limit 100
```

### Custom Output File
```bash
python detect_dns_abuse_enhanced.py --csv data.csv --output results.csv
```

### CSV Only (No Google Sheets)
```bash
python detect_dns_abuse_enhanced.py --csv data.csv --no-google-output
```

### Different Model
```bash
python detect_dns_abuse_enhanced.py --csv data.csv --model lightgbm_dns_abuse_model.pkl
```

---

## Workflow: Live Detection Pipeline

**Step 1:** Capture traffic with CIC-Flow-Meter
```bash
java -jar CICFlowMeter.jar --google --sheet SHEET_ID --credentials credentials.json
```

**Step 2:** Run detection
```bash
python detect_dns_abuse_enhanced.py --sheet SHEET_ID --credentials credentials.json
```

**Step 3:** Review results
- CSV file: `dns_detection_enhanced_YYYYMMDD_HHMMSS.csv`
- Google Sheet ID: Displayed in console
- Filter by `risk_level = CRITICAL`

---

## Testing

Run test suite:
```bash
python test_enhanced_detection.py
```

Expected: `4/4 tests passed`

---

## Files

- `detect_dns_abuse_enhanced.py` - Main script (24 KB)
- `ENHANCED_DETECTION_GUIDE.md` - Full documentation
- `test_enhanced_detection.py` - Test suite
- `QUICKREF.md` - This file

---

## Example Output

```csv
src_ip,dst_ip,...,timestamp_range,prediction_label,confidence_score,risk_level
192.168.1.100,8.8.8.8,...,2026-01-03 14:00 to 14:30,ATTACK,0.95,CRITICAL
192.168.1.101,1.1.1.1,...,2026-01-03 14:00 to 14:30,BENIGN,0.92,CRITICAL
```

---

## Troubleshooting

**Model not found:**
```bash
python detect_dns_abuse_enhanced.py --model "C:\path\to\model.pkl" --csv data.csv
```

**Google Sheets auth error:**
- Share sheet with service account email
- Check credentials.json permissions

**Required packages:**
```bash
pip install -r requirements_detection.txt
```

---

For full documentation, see: `ENHANCED_DETECTION_GUIDE.md`
