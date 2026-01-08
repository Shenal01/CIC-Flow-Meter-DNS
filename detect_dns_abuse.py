"""
DNS Abuse Detection Script with Google Sheets Integration

This script detects DNS abuse and infrastructure attacks using a trained XGBoost model.
It supports reading data from both local CSV files and Google Sheets.

Usage:
    # Detect from local CSV file
    python detect_dns_abuse.py --csv path/to/data.csv
    
    # Detect from Google Sheets
    python detect_dns_abuse.py --sheet SPREADSHEET_ID --credentials path/to/credentials.json
    
    # With output file
    python detect_dns_abuse.py --csv data.csv --output results.csv
    
    # Limit number of rows to process
    python detect_dns_abuse.py --csv data.csv --limit 1000

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

# Google Sheets imports (optional, only needed if using --sheet option)
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    GOOGLE_SHEETS_AVAILABLE = True
except ImportError:
    GOOGLE_SHEETS_AVAILABLE = False


class DNSAbuseDetector:
    """Detects DNS abuse using a trained XGBoost model."""
    
    def __init__(self, model_path):
        """
        Initialize the detector with a trained model.
        
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
    
    def preprocess_data(self, df):
        """
        Preprocess data to match training format.
        
        Args:
            df (pd.DataFrame): Raw data
            
        Returns:
            tuple: (X_features, y_labels, has_labels)
        """
        print(f"\n{'='*80}")
        print("PREPROCESSING DATA")
        print(f"{'='*80}")
        
        # Create a copy
        df_clean = df.copy()
        
        # 1. Handle infinite and NaN values
        print("\n1. Handling infinite and NaN values...")
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_clean.fillna(0, inplace=True)
        print("   [OK] Infinite/NaN values handled")
        
        # 2. Drop identity columns
        print("\n2. Dropping identity columns...")
        columns_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
        existing_cols_to_drop = [col for col in columns_to_drop if col in df_clean.columns]
        df_clean = df_clean.drop(columns=existing_cols_to_drop, errors='ignore')
        if existing_cols_to_drop:
            print(f"   [OK] Dropped {len(existing_cols_to_drop)} columns: {existing_cols_to_drop}")
        else:
            print(f"   [OK] No identity columns to drop")
        
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
        
        return X, y, has_labels
    
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
    
    def save_results(self, X, predictions, probabilities, y_true=None, output_path=None):
        """
        Save prediction results to a CSV file.
        
        Args:
            X (pd.DataFrame): Original features
            predictions (np.array): Model predictions
            probabilities (np.array): Prediction probabilities
            y_true (pd.Series, optional): True labels if available
            output_path (str, optional): Output file path
        """
        print(f"\n{'='*80}")
        print("SAVING RESULTS")
        print(f"{'='*80}")
        
        # Create results DataFrame
        results_df = pd.DataFrame({
            'prediction': predictions,
            'prediction_label': ['BENIGN' if p == 0 else 'ATTACK' for p in predictions],
            'confidence_benign': probabilities[:, 0],
            'confidence_attack': probabilities[:, 1],
            'confidence': [max(p) for p in probabilities]
        })
        
        # Add true labels if available
        if y_true is not None:
            results_df['actual'] = y_true.values
            results_df['actual_label'] = ['BENIGN' if a == 0 else 'ATTACK' for a in y_true]
            results_df['correct'] = (y_true.values == predictions)
            accuracy = (predictions == y_true.values).mean()
            print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        
        # Determine output path
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"dns_abuse_predictions_{timestamp}.csv"
        
        # Save to CSV
        results_df.to_csv(output_path, index=False)
        print(f"\n[OK] Results saved to: {output_path}")
        print(f"   - Total predictions: {len(results_df):,}")
        
        # Show sample predictions
        print(f"\nSample Predictions (first 10):")
        print(results_df.head(10).to_string(index=False))
        
        return results_df


def main():
    """Main entry point for the detection script."""
    
    parser = argparse.ArgumentParser(
        description='Detect DNS abuse using trained XGBoost model',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect from CSV file
  python detect_dns_abuse.py --csv traffic_data.csv
  
  # Detect from Google Sheets
  python detect_dns_abuse.py --sheet 1ABC...XYZ --credentials credentials.json
  
  # With custom output file
  python detect_dns_abuse.py --csv data.csv --output results.csv
  
  # Limit number of rows
  python detect_dns_abuse.py --csv data.csv --limit 1000
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
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.sheet and not args.credentials:
        parser.error("--credentials is required when using --sheet")
    
    try:
        # Initialize detector
        detector = DNSAbuseDetector(args.model)
        
        # Load data
        if args.csv:
            df = detector.read_csv_data(args.csv, limit=args.limit)
        else:
            df = detector.read_google_sheets_data(
                args.sheet,
                args.credentials,
                sheet_name=args.sheet_name,
                limit=args.limit
            )
        
        # Preprocess data
        X, y, has_labels = detector.preprocess_data(df)
        
        # Make predictions
        predictions, probabilities = detector.predict(X)
        
        # Save results
        results = detector.save_results(X, predictions, probabilities, y, args.output)
        
        # Final summary
        print(f"\n{'='*80}")
        print("DETECTION COMPLETE")
        print(f"{'='*80}")
        print(f"\n[OK] Detection completed successfully!")
        
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
