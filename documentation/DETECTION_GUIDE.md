# DNS Abuse Detection Script - User Guide

This guide explains how to use the `detect_dns_abuse.py` script to detect DNS abuse and infrastructure attacks using the trained XGBoost model.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Google Sheets Setup](#google-sheets-setup)
- [Output Format](#output-format)
- [Troubleshooting](#troubleshooting)

## Installation

### Requirements

```bash
# Install required Python packages
pip install -r requirements_detection.txt
```

### Required Files

1. **Model File**: `xgboost_dns_abuse_infrastructure_model.pkl` (in the same directory)
2. **Data Source**: Either a CSV file or Google Sheets access
3. **Credentials** (for Google Sheets): Service account JSON file

## Quick Start

### Detect from CSV File

```bash
python detect_dns_abuse.py --csv path/to/traffic_data.csv
```

### Detect from Google Sheets

```bash
python detect_dns_abuse.py --sheet SPREADSHEET_ID --credentials credentials.json
```

## Usage Examples

### Example 1: Basic CSV Detection

Detect DNS abuse from a local CSV file:

```bash
python detect_dns_abuse.py --csv traffic_data.csv
```

**Output**: Auto-generated file `dns_abuse_predictions_YYYYMMDD_HHMMSS.csv`

### Example 2: CSV with Custom Output

Specify a custom output filename:

```bash
python detect_dns_abuse.py --csv traffic_data.csv --output my_results.csv
```

### Example 3: Process Limited Rows

Process only the first 1000 rows (useful for testing):

```bash
python detect_dns_abuse.py --csv large_file.csv --limit 1000
```

### Example 4: Google Sheets Detection

Detect from a Google Sheet:

```bash
python detect_dns_abuse.py \
  --sheet 1ABC123xyz...SpreadsheetID \
  --credentials service_account.json
```

### Example 5: Google Sheets with Specific Sheet Tab

If your spreadsheet has multiple tabs:

```bash
python detect_dns_abuse.py \
  --sheet 1ABC123xyz...SpreadsheetID \
  --credentials service_account.json \
  --sheet-name "DNS Traffic Data"
```

### Example 6: Custom Model Path

Use a different model file:

```bash
python detect_dns_abuse.py \
  --model lightgbm_dns_abuse_model.pkl \
  --csv traffic_data.csv
```

## Google Sheets Setup

To use Google Sheets as a data source, follow these steps:

### 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable the **Google Sheets API**:
   - Go to "APIs & Services" > "Library"
   - Search for "Google Sheets API"
   - Click "Enable"

### 2. Create Service Account

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "Service Account"
3. Fill in details:
   - Service account name: `dns-detector`
   - Role: (can leave blank or select "Viewer")
4. Click "Done"

### 3. Download Credentials

1. Click on the created service account
2. Go to "Keys" tab
3. Click "Add Key" > "Create new key"
4. Choose "JSON" format
5. Download and save as `credentials.json`

### 4. Share Google Sheet

1. Open your Google Sheet in browser
2. Click the "Share" button (top-right)
3. Add the service account email (found in `credentials.json` as `client_email`)
   - Example: `dns-detector@your-project.iam.gserviceaccount.com`
4. Grant "Viewer" permission (or "Editor" if needed)
5. Uncheck "Notify people"
6. Click "Share"

### 5. Get Spreadsheet ID

The spreadsheet ID is in the URL:
```
https://docs.google.com/spreadsheets/d/SPREADSHEET_ID_HERE/edit
                                        ^^^^^^^^^^^^^^^^^^
```

Copy this ID for use with `--sheet` parameter.

## Output Format

The script generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `prediction` | Numeric prediction (0 = BENIGN, 1 = ATTACK) |
| `prediction_label` | Human-readable label (BENIGN or ATTACK) |
| `confidence_benign` | Probability of being benign (0.0 to 1.0) |
| `confidence_attack` | Probability of being attack (0.0 to 1.0) |
| `confidence` | Maximum confidence score |
| `actual` | True label (only if input has labels) |
| `actual_label` | True label in human-readable format |
| `correct` | Whether prediction matches actual (only if labels available) |

### Sample Output

```csv
prediction,prediction_label,confidence_benign,confidence_attack,confidence,actual,actual_label,correct
0,BENIGN,0.9234,0.0766,0.9234,0,BENIGN,True
1,ATTACK,0.1245,0.8755,0.8755,1,ATTACK,True
0,BENIGN,0.8901,0.1099,0.8901,0,BENIGN,True
1,ATTACK,0.0523,0.9477,0.9477,1,ATTACK,True
```

## Troubleshooting

### Error: Model file not found

**Solution**: Ensure `xgboost_dns_abuse_infrastructure_model.pkl` is in the current directory or specify the full path:

```bash
python detect_dns_abuse.py --model "C:\path\to\model.pkl" --csv data.csv
```

### Error: CSV file not found

**Solution**: Use the full absolute path to the CSV file:

```bash
python detect_dns_abuse.py --csv "C:\Users\...\data.csv"
```

### Error: Google Sheets permission denied

**Solution**: Make sure you've shared the Google Sheet with the service account email (found in `credentials.json`).

### Error: Feature count mismatch

**Solution**: Your input data doesn't have the same features as the training data. Check:
- Column names match exactly
- No missing features
- No extra features (except `label` which is handled automatically)

### Warning: Google Sheets libraries not available

**Solution**: Install Google Sheets dependencies:

```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

## Command-Line Reference

```
usage: detect_dns_abuse.py [-h] [--model MODEL] (--csv CSV | --sheet SHEET)
                           [--credentials CREDENTIALS] [--sheet-name SHEET_NAME]
                           [--output OUTPUT] [--limit LIMIT]

optional arguments:
  -h, --help            Show help message and exit
  --model MODEL         Path to trained model file
  --csv CSV            Path to CSV file
  --sheet SHEET        Google Sheets spreadsheet ID
  --credentials CREDENTIALS
                       Path to Google credentials JSON
  --sheet-name SHEET_NAME
                       Name of sheet tab in Google Sheets
  --output OUTPUT      Output CSV file path
  --limit LIMIT        Maximum rows to process
```

## CSV Data Format Requirements

Your CSV file should contain the same features used during model training. Common features include:

- Flow duration
- Packet counts (forward/backward)
- Byte counts (forward/backward)
- Packet length statistics
- Inter-arrival times
- Flow rates
- DNS-specific features
- Protocol type

**Optional**: A `label` column (0 = BENIGN, 1 = ATTACK) for validation purposes.

## Tips

1. **Test with Limited Rows**: Use `--limit 100` to test the script on a small sample first
2. **Save Credentials Securely**: Never commit `credentials.json` to version control
3. **Check Model Path**: Ensure the model file path is correct
4. **Validate Data Format**: Make sure your CSV/Sheet has the correct column names
5. **Monitor Confidence Scores**: Low confidence scores may indicate uncertain predictions

## Support

For issues or questions:
- Check the error message carefully
- Verify all file paths are correct
- Ensure credentials have proper permissions
- Review the preprocessing steps in the script
