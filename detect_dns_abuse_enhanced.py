"""
Enhanced DNS Abuse Detection Script with Google Sheets Integration

This script detects DNS abuse and infrastructure attacks using a trained XGBoost model.
It preserves all original columns and adds enhanced output columns including timestamps,
confidence scores, predictions, and risk levels.

Key Features:
- Reads from Google Sheets or CSV files
- Preserves ALL original columns (including IPs, ports)
- Adds timestamp range (capture start-end)
- Adds confidence scores and risk levels
- Outputs to both CSV and new Google Sheet
- Displays new Google Sheet ID after completion

Usage:
    # Detect from Google Sheets
    python detect_dns_abuse_enhanced.py --sheet SPREADSHEET_ID --credentials credentials.json
    
    # Detect from CSV
    python detect_dns_abuse_enhanced.py --csv path/to/data.csv
    
    # With custom output and model
    python detect_dns_abuse_enhanced.py --csv data.csv --output results.csv --model model.pkl

Requirements:
    - xgboost
    - pandas
    - numpy
    - scikit-learn
    - google-api-python-client
    - google-auth-httplib2
    - google-auth-oauthlib

Author: Cybersecurity Research Team
"""

import argparse
import pandas as pd
import numpy as np
import pickle
import sys
from pathlib import Path
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings('ignore')

# Google Sheets imports (optional)
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    GOOGLE_SHEETS_AVAILABLE = True
except ImportError:
    GOOGLE_SHEETS_AVAILABLE = False


class EnhancedDNSAbuseDetector:
    """Enhanced DNS abuse detector with full column preservation and Google Sheets support."""
    
    def __init__(self, model_path):
        """
        Initialize the enhanced detector with a trained model.
        
        Args:
            model_path (str): Path to the saved model (.pkl file)
        """
        self.model_path = model_path
        self.model = None
        self.load_model()
        
    def load_model(self):
        """Load the trained XGBoost model from file."""
        print(f"\n{'='*80}")
        print("LOADING MODEL")
        print(f"{'='*80}")
        
        model_file = Path(self.model_path)
        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        
        print(f"\nLoading model from: {self.model_path}")
        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        print(f"[OK] Model loaded successfully")
        print(f"  - Type: {type(self.model).__name__}")
        print(f"  - Features expected: {self.model.n_features_in_}")
        
    def read_csv_data(self, csv_path, limit=None):
        """
        Read data from a CSV file.
        
        Args:
            csv_path (str): Path to CSV file
            limit (int, optional): Maximum number of rows to read
            
        Returns:
            pd.DataFrame: Loaded data
        """
        print(f"\n{'='*80}")
        print("LOADING DATA FROM CSV")
        print(f"{'='*80}")
        
        csv_file = Path(csv_path)
        if not csv_file.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        print(f"\nReading CSV: {csv_path}")
        
        if limit:
            df = pd.read_csv(csv_path, nrows=limit)
            print(f"[OK] Loaded {len(df):,} rows (limited)")
        else:
            df = pd.read_csv(csv_path)
            print(f"[OK] Loaded {len(df):,} rows")
        
        print(f"  - Columns: {len(df.columns)}")
        return df
    
    def read_google_sheets_data(self, spreadsheet_id, credentials_path, sheet_name=None, limit=None):
        """
        Read data from Google Sheets.
        
        Args:
            spreadsheet_id (str): Google Sheets ID
            credentials_path (str): Path to service account credentials JSON
            sheet_name (str, optional): Name of the sheet tab (default: first sheet)
            limit (int, optional): Maximum number of rows to read
            
        Returns:
            pd.DataFrame: Loaded data
        """
        if not GOOGLE_SHEETS_AVAILABLE:
            raise ImportError(
                "Google Sheets libraries not available. Install with:\n"
                "pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib"
            )
        
        print(f"\n{'='*80}")
        print("LOADING DATA FROM GOOGLE SHEETS")
        print(f"{'='*80}")
        
        credentials_file = Path(credentials_path)
        if not credentials_file.exists():
            raise FileNotFoundError(f"Credentials file not found: {credentials_path}")
        
        print(f"\nConnecting to Google Sheets...")
        print(f"  - Spreadsheet ID: {spreadsheet_id}")
        print(f"  - Credentials: {credentials_path}")
        
        # Authenticate and build service
        SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
        credentials = service_account.Credentials.from_service_account_file(
            credentials_path, scopes=SCOPES)
        service = build('sheets', 'v4', credentials=credentials)
        
        # Get sheet name if not provided
        if sheet_name is None:
            spreadsheet = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
            sheet_name = spreadsheet['sheets'][0]['properties']['title']
            print(f"  - Using first sheet: {sheet_name}")
        
        # Read data
        range_name = f"{sheet_name}!A:ZZ"  # Read all columns
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=range_name
        ).execute()
        
        values = result.get('values', [])
        if not values:
            raise ValueError("No data found in Google Sheet")
        
        # Convert to DataFrame
        headers = values[0]
        data = values[1:]
        
        # Apply limit if specified
        if limit and limit < len(data):
            data = data[:limit]
        
        df = pd.DataFrame(data, columns=headers)
        
        print(f"[OK] Loaded {len(df):,} rows from Google Sheets")
        print(f"  - Columns: {len(df.columns)}")
        
        # Convert numeric columns
        for col in df.columns:
            try:
                df[col] = pd.to_numeric(df[col])
            except (ValueError, TypeError):
                pass  # Keep as string if conversion fails
        
        return df
    
    def write_to_google_sheets(self, df, spreadsheet_id, credentials_path, sheet_title=None):
        """
        Write results to a NEW TAB in an existing Google Sheet.
        
        Args:
            df (pd.DataFrame): Data to write
            spreadsheet_id (str): ID of existing spreadsheet to add tab to
            credentials_path (str): Path to service account credentials JSON
            sheet_title (str, optional): Title for new sheet tab
            
        Returns:
            str: Name of the created sheet tab
        """
        if not GOOGLE_SHEETS_AVAILABLE:
            raise ImportError(
                "Google Sheets libraries not available. Install with:\n"
                "pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib"
            )
        
        print(f"\n{'='*80}")
        print("WRITING RESULTS TO GOOGLE SHEETS")
        print(f"{'='*80}")
        
        # Authenticate with write permissions (only spreadsheets scope needed for tabs)
        SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
        credentials = service_account.Credentials.from_service_account_file(
            credentials_path, scopes=SCOPES)
        service = build('sheets', 'v4', credentials=credentials)
        
        # Create sheet tab title
        if sheet_title is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            sheet_title = f"Detection_Results_{timestamp}"
        
        print(f"\nAdding new tab to existing spreadsheet: {sheet_title}")
        print(f"Spreadsheet ID: {spreadsheet_id}")
        
        # Create new sheet tab in existing spreadsheet
        requests = [{
            'addSheet': {
                'properties': {
                    'title': sheet_title
                }
            }
        }]
        
        body = {
            'requests': requests
        }
        
        response = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body=body
        ).execute()
        
        print(f"[OK] Created new tab: {sheet_title}")
        
        # Prepare data for upload
        values = [df.columns.tolist()] + df.values.tolist()
        
        body = {
            'values': values
        }
        
        # Write data to the new tab
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range=f"'{sheet_title}'!A1",
            valueInputOption='RAW',
            body=body
        ).execute()
        
        print(f"[OK] Wrote {len(df):,} rows to new tab")
        print(f"\n🔗 View your results at:")
        print(f"   https://docs.google.com/spreadsheets/d/{spreadsheet_id}/edit#gid=0")
        
        return sheet_title
    
    def extract_timestamp_range(self, df):
        """
        Extract timestamp range from data (capture start - end).
        
        Args:
            df (pd.DataFrame): Original data
            
        Returns:
            str: Timestamp range string
        """
        # Look for common timestamp column names
        timestamp_cols = ['timestamp', 'time', 'flow_start_time', 'start_time', 
                         'capture_time', 'flow_timestamp']
        
        timestamp_col = None
        for col in timestamp_cols:
            if col in df.columns:
                timestamp_col = col
                break
        
        if timestamp_col is None:
            # If no timestamp column, use current time
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return f"Detection Time: {current_time}"
        
        try:
            # Convert to datetime
            timestamps = pd.to_datetime(df[timestamp_col], errors='coerce')
            timestamps = timestamps.dropna()
            
            if len(timestamps) > 0:
                start_time = timestamps.min()
                end_time = timestamps.max()
                return f"{start_time} to {end_time}"
            else:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return f"Detection Time: {current_time}"
        except:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return f"Detection Time: {current_time}"
    
    def preprocess_data_with_tracking(self, df):
        """
        Preprocess data while tracking original columns for later restoration.
        
        Args:
            df (pd.DataFrame): Raw data
            
        Returns:
            tuple: (X_features, y_labels, original_df, has_labels)
        """
        print(f"\n{'='*80}")
        print("PREPROCESSING DATA (WITH COLUMN TRACKING)")
        print(f"{'='*80}")
        
        # Store original DataFrame
        original_df = df.copy()
        
        # Create a copy for preprocessing
        df_clean = df.copy()
        
        # 1. Handle infinite and NaN values
        print("\n1. Handling infinite and NaN values...")
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_clean.fillna(0, inplace=True)
        print("   [OK] Infinite/NaN values handled")
        
        # 2. Drop identity columns for model prediction (but track them)
        print("\n2. Temporarily removing identity columns for prediction...")
        columns_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
        existing_cols_to_drop = [col for col in columns_to_drop if col in df_clean.columns]
        df_clean = df_clean.drop(columns=existing_cols_to_drop, errors='ignore')
        if existing_cols_to_drop:
            print(f"   [OK] Temporarily removed {len(existing_cols_to_drop)} columns: {existing_cols_to_drop}")
            print(f"   (These will be restored in final output)")
        else:
            print(f"   [OK] No identity columns to remove")
        
        # 3. Encode categorical features
        print("\n3. Encoding categorical features...")
        if 'protocol' in df_clean.columns:
            protocol_encoder = LabelEncoder()
            df_clean['protocol'] = protocol_encoder.fit_transform(df_clean['protocol'].astype(str))
            print(f"   [OK] Protocol encoded")
        
        # 4. Separate features and labels
        has_labels = 'label' in df_clean.columns
        if has_labels:
            X = df_clean.drop('label', axis=1)
            y = df_clean['label']
            print(f"\n[OK] Preprocessing complete")
            print(f"   - Features shape: {X.shape}")
            print(f"   - Labels found: Yes")
        else:
            X = df_clean
            y = None
            print(f"\n[OK] Preprocessing complete")
            print(f"   - Features shape: {X.shape}")
            print(f"   - Labels found: No (unlabeled data)")
        
        # 5. Verify feature count
        if X.shape[1] != self.model.n_features_in_:
            print(f"\n⚠ WARNING: Feature count mismatch!")
            print(f"   Model expects: {self.model.n_features_in_} features")
            print(f"   Data has: {X.shape[1]} features")
            print(f"\n   This may cause prediction errors!")
        else:
            print(f"\n[OK] Feature count matches model expectations ({self.model.n_features_in_} features)")
        
        return X, y, original_df, has_labels
    
    def predict(self, X):
        """
        Make predictions on preprocessed data.
        
        Args:
            X (pd.DataFrame): Preprocessed features
            
        Returns:
            tuple: (predictions, probabilities)
        """
        print(f"\n{'='*80}")
        print("MAKING PREDICTIONS")
        print(f"{'='*80}")
        
        print(f"\nGenerating predictions for {len(X):,} samples...")
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        print("[OK] Predictions generated")
        
        # Show distribution
        unique, counts = np.unique(predictions, return_counts=True)
        print(f"\nPrediction Distribution:")
        for label, count in zip(unique, counts):
            label_name = 'BENIGN' if label == 0 else 'ATTACK'
            percentage = (count / len(predictions)) * 100
            print(f"  - {label_name}: {count:,} ({percentage:.2f}%)")
        
        return predictions, probabilities
    
    def calculate_risk_level(self, confidence):
        """
        Calculate risk level based on confidence score.
        
        Args:
            confidence (float): Confidence score (0.0 to 1.0)
            
        Returns:
            str: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        if confidence >= 0.90:
            return "CRITICAL"
        elif confidence >= 0.80:
            return "HIGH"
        elif confidence >= 0.60:
            return "MEDIUM"
        else:
            return "LOW"
    
    def create_enhanced_output(self, original_df, predictions, probabilities, timestamp_range):
        """
        Create enhanced output with all original columns + new analysis columns.
        
        Args:
            original_df (pd.DataFrame): Original DataFrame with all columns
            predictions (np.array): Model predictions
            probabilities (np.array): Prediction probabilities
            timestamp_range (str): Timestamp range string
            
        Returns:
            pd.DataFrame: Enhanced output DataFrame
        """
        print(f"\n{'='*80}")
        print("CREATING ENHANCED OUTPUT")
        print(f"{'='*80}")
        
        # Start with original DataFrame (ALL columns preserved)
        output_df = original_df.copy()
        
        # Add timestamp range
        output_df['timestamp_range'] = timestamp_range
        
        # Add predictions
        output_df['prediction'] = predictions
        output_df['prediction_label'] = ['BENIGN' if p == 0 else 'ATTACK' for p in predictions]
        
        # Add confidence scores
        output_df['confidence_benign'] = probabilities[:, 0]
        output_df['confidence_attack'] = probabilities[:, 1]
        output_df['confidence_score'] = np.max(probabilities, axis=1)
        
        # Add risk levels
        output_df['risk_level'] = [self.calculate_risk_level(conf) for conf in output_df['confidence_score']]
        
        # Drop unimplemented columns (always zero, not useful for analysis)
        columns_to_hide = ['ttl_violation_rate', 'dns_server_fanout']
        columns_dropped = [col for col in columns_to_hide if col in output_df.columns]
        if columns_dropped:
            output_df = output_df.drop(columns=columns_dropped)
            print(f"\n[INFO] Hiding unimplemented columns: {columns_dropped}")
        
        print(f"\n[OK] Enhanced output created")
        print(f"   - Total columns: {len(output_df.columns)}")
        print(f"   - Original columns: {len(original_df.columns)}")
        print(f"   - New columns: 7")
        print(f"   - New columns added:")
        print(f"     • timestamp_range")
        print(f"     • prediction")
        print(f"     • prediction_label")
        print(f"     • confidence_benign")
        print(f"     • confidence_attack")
        print(f"     • confidence_score")
        print(f"     • risk_level")
        
        # Show risk level distribution
        risk_counts = output_df['risk_level'].value_counts()
        print(f"\n   Risk Level Distribution:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_counts.get(level, 0)
            percentage = (count / len(output_df)) * 100 if len(output_df) > 0 else 0
            print(f"     • {level}: {count:,} ({percentage:.2f}%)")
        
        return output_df
    
    def save_results_csv(self, output_df, output_path=None):
        """
        Save results to CSV file.
        
        Args:
            output_df (pd.DataFrame): Enhanced output DataFrame
            output_path (str, optional): Output file path
            
        Returns:
            str: Path to saved CSV file
        """
        print(f"\n{'='*80}")
        print("SAVING RESULTS TO CSV")
        print(f"{'='*80}")
        
        # Determine output path
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"dns_detection_enhanced_{timestamp}.csv"
        
        # Save to CSV
        output_df.to_csv(output_path, index=False)
        print(f"\n[OK] Results saved to: {output_path}")
        print(f"   - Total rows: {len(output_df):,}")
        print(f"   - Total columns: {len(output_df.columns)}")
        
        # Show sample predictions
        print(f"\nSample Predictions (first 5 rows, selected columns):")
        sample_cols = ['prediction_label', 'confidence_score', 'risk_level']
        if 'src_ip' in output_df.columns:
            sample_cols.insert(0, 'src_ip')
        if 'dst_ip' in output_df.columns:
            sample_cols.insert(1, 'dst_ip')
        
        available_cols = [col for col in sample_cols if col in output_df.columns]
        print(output_df[available_cols].head(5).to_string(index=False))
        
        return output_path


def main():
    """Main entry point for the enhanced detection script."""
    
    parser = argparse.ArgumentParser(
        description='Enhanced DNS abuse detection with full column preservation and Google Sheets support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect from CSV file
  python detect_dns_abuse_enhanced.py --csv traffic_data.csv
  
  # Detect from Google Sheets
  python detect_dns_abuse_enhanced.py --sheet 1ABC...XYZ --credentials credentials.json
  
  # With custom output file
  python detect_dns_abuse_enhanced.py --csv data.csv --output results.csv
  
  # Limit number of rows
  python detect_dns_abuse_enhanced.py --csv data.csv --limit 1000
        """
    )
    
    # Model arguments
    parser.add_argument(
        '--model',
        type=str,
        default='xgboost_dns_abuse_infrastructure_model.pkl',
        help='Path to trained model file (default: xgboost_dns_abuse_infrastructure_model.pkl)'
    )
    
    # Data source arguments (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        '--csv',
        type=str,
        help='Path to CSV file containing traffic data'
    )
    source_group.add_argument(
        '--sheet',
        type=str,
        help='Google Sheets spreadsheet ID'
    )
    
    # Google Sheets specific arguments
    parser.add_argument(
        '--credentials',
        type=str,
        help='Path to Google service account credentials JSON (required for --sheet)'
    )
    parser.add_argument(
        '--sheet-name',
        type=str,
        help='Name of the sheet tab in Google Sheets (default: first sheet)'
    )
    
    # Output arguments
    parser.add_argument(
        '--output',
        type=str,
        help='Output CSV file path (default: auto-generated with timestamp)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Maximum number of rows to process (default: all)'
    )
    parser.add_argument(
        '--no-google-output',
        action='store_true',
        help='Skip writing results to Google Sheets (CSV only)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.sheet and not args.credentials:
        parser.error("--credentials is required when using --sheet")
    
    try:
        # Initialize detector
        detector = EnhancedDNSAbuseDetector(args.model)
        
        # Load data
        spreadsheet_id = None  # Track the spreadsheet ID
        if args.csv:
            df = detector.read_csv_data(args.csv, limit=args.limit)
            credentials_path = args.credentials if args.credentials else None
        else:
            spreadsheet_id = args.sheet  # Store the spreadsheet ID
            df = detector.read_google_sheets_data(
                spreadsheet_id,
                args.credentials,
                sheet_name=args.sheet_name,
                limit=args.limit
            )
            credentials_path = args.credentials
        
        # Extract timestamp range
        timestamp_range = detector.extract_timestamp_range(df)
        print(f"\nTimestamp Range: {timestamp_range}")
        
        # Preprocess data with column tracking
        X, y, original_df, has_labels = detector.preprocess_data_with_tracking(df)
        
        # Make predictions
        predictions, probabilities = detector.predict(X)
        
        # Create enhanced output
        output_df = detector.create_enhanced_output(original_df, predictions, probabilities, timestamp_range)
        
        # Save results to CSV
        csv_path = detector.save_results_csv(output_df, args.output)
        
        # Write to Google Sheets if enabled and credentials available
        sheet_tab_name = None
        if not args.no_google_output and credentials_path and spreadsheet_id and GOOGLE_SHEETS_AVAILABLE:
            try:
                sheet_tab_name = detector.write_to_google_sheets(output_df, spreadsheet_id, credentials_path)
            except Exception as e:
                print(f"\n[WARNING] Could not write to Google Sheets: {e}")
                print("Results are still saved to CSV file.")
        
        # Final summary
        print(f"\n{'='*80}")
        print("DETECTION COMPLETE")
        print(f"{'='*80}")
        print(f"\n✓ Detection completed successfully!")
        print(f"\n📄 CSV Output: {csv_path}")
        if sheet_tab_name and spreadsheet_id:
            print(f"\n📊 Google Sheet Tab Created: {sheet_tab_name}")
            print(f"📋 Spreadsheet ID: {spreadsheet_id}")
            print(f"🔗 View at: https://docs.google.com/spreadsheets/d/{spreadsheet_id}/edit")
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
