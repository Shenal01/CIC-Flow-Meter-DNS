# Quick Start Examples for DNS Abuse Detection

## Example 1: Detect from Existing Test CSV (Simple)
```bash
cd C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS
python detect_dns_abuse.py --csv "C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\benign_generated_mix.csv" --limit 100
```

## Example 2: Detect with Custom Output
```bash
python detect_dns_abuse.py --csv "C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\benign_generated_mix.csv" --output benign_detection_results.csv
```

## Example 3: Google Sheets Detection (when ready)
```bash
# First, set up Google Sheets API and get credentials.json
# Then share your sheet with the service account email
python detect_dns_abuse.py --sheet YOUR_SPREADSHEET_ID --credentials credentials.json
```

## What the Script Does:

1. ✅ Loads your trained XGBoost model (`xgboost_dns_abuse_infrastructure_model.pkl`)
2. ✅ Reads data from CSV or Google Sheets
3. ✅ Applies the same preprocessing as training (handles NaN, drops identity columns, encodes protocol)
4. ✅ Makes predictions with confidence scores
5. ✅ Saves results to CSV with:
   - Prediction (0=BENIGN, 1=ATTACK)
   - Confidence scores for both classes
   - If labels exist: accuracy and correctness per row

## Installation:
```bash
pip install -r requirements_detection.txt
```

## See Full Documentation:
- [DETECTION_GUIDE.md](file:///C:/Users/shenal/Downloads/reseraach/CIC-Flow-Meter-DNS/DETECTION_GUIDE.md) - Complete usage guide
