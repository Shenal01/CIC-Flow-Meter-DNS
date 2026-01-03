"""
Test Script for LightGBM DNS Abuse Detection Model

This script loads a trained LightGBM model and tests it on a provided dataset.
It handles preprocessing (feature selection, encoding) and generates predictions.
"""

import pandas as pd
import numpy as np
import lightgbm as lgb
import os
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ============================================================================
# CONFIGURATION
# ============================================================================

# Model file path
MODEL_FILE = 'lightgbm_dns_abuse_model.txt' 

# Test data file path (User Provided)
TEST_DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\benign_generated_org.csv'

# Output predictions file
OUTPUT_FILE = 'lightgbm_test_predictions.csv'

# ============================================================================
# 1. LOAD MODEL
# ============================================================================
print("=" * 60)
print("LOADING MODEL")
print("=" * 60)

if not os.path.exists(MODEL_FILE):
    print(f"[ERROR] Error: Model file not found at {MODEL_FILE}")
    print("Please ensure you have trained the model using the notebook first.")
    exit(1)

print(f"Loading model from: {MODEL_FILE}")
try:
    bst = lgb.Booster(model_file=MODEL_FILE)
    bst = lgb.Booster(model_file=MODEL_FILE)
    print("[OK] Model loaded successfully")
except Exception as e:
    print(f"[ERROR] Failed to load model: {e}")
    exit(1)

# ============================================================================
# 2. LOAD TEST DATA
# ============================================================================
print("\n" + "=" * 60)
print("LOADING TEST DATA")
print("=" * 60)

print(f"Loading data from: {TEST_DATA_PATH}")

try:
    df_test = pd.read_csv(TEST_DATA_PATH)
    print(f"[OK] Data loaded. Shape: {df_test.shape}")
except FileNotFoundError:
    print(f"[ERROR] Error: Test data file not found at {TEST_DATA_PATH}")
    exit(1)
except Exception as e:
    print(f"[ERROR] Error loading data: {e}")
    exit(1)

# ============================================================================
# 3. PREPROCESSING
# ============================================================================
print("\n" + "=" * 60)
print("PREPROCESSING")
print("=" * 60)

# A. Clean Infinite/NaN
print("Handling NaN/Infinite values...")
df_test.replace([np.inf, -np.inf], np.nan, inplace=True)
df_test.fillna(0, inplace=True)

# B. Drop Identity Columns
cols_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
existing_cols = [c for c in cols_to_drop if c in df_test.columns]
if existing_cols:
    print(f"Dropping identity columns: {existing_cols}")
    df_test_clean = df_test.drop(columns=existing_cols)
else:
    df_test_clean = df_test.copy()

# C. Encode Protocol
if 'protocol' in df_test_clean.columns:
    if df_test_clean['protocol'].dtype == 'object':
        print("Encoding protocol column...")
        le = LabelEncoder()
        # Note: In a real production pipeline, you should load the encoder saved during training.
        # Here we assume standard 'TCP', 'UDP' values.
        # We enforce the mapping: TCP=0, UDP=1 based on training logic.
        
        # Custom mapping to ensure consistency with training
        protocol_map = {'TCP': 0, 'UDP': 1}
        # Handle unknown protocols by defaulting to UDP (common for DNS) or 0
        df_test_clean['protocol'] = df_test_clean['protocol'].map(protocol_map).fillna(1).astype(int)
        print("[OK] Protocol encoded (TCP=0, UDP=1)")

# Prepare Features
if 'label' in df_test_clean.columns:
    X_test = df_test_clean.drop('label', axis=1)
    y_test = df_test_clean['label']
    has_labels = True
else:
    X_test = df_test_clean
    y_test = None
    has_labels = False

print(f"Features for prediction: {X_test.shape[1]}")

# ============================================================================
# 4. PREDICTION
# ============================================================================
print("\n" + "=" * 60)
print("PREDICTION")
print("=" * 60)

print("Generating predictions...")
# Predict returns probabilities for the positive class (1 = Malicious)
y_prob = bst.predict(X_test)
# Threshold at 0.5 for binary classification
y_pred = [1 if p >= 0.5 else 0 for p in y_prob]

# Metrics if labels exist
if has_labels:
    print("\n--- PERFORMANCE METRICS ---")
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
else:
    print("\nNo labels provided. Detailed accuracy metrics skipped.")

# Distribution
# Distribution
unique, counts = np.unique(y_pred, return_counts=True)
count_dict = dict(zip(unique, counts))
benign_count = count_dict.get(0, 0)
attack_count = count_dict.get(1, 0)
total_count = len(y_pred)

print("\n" + "#" * 60)
print("FINAL PREDICTION SUMMARY")
print("#" * 60)
print(f"\nTotal Samples: {total_count:,}")
print(f"DETECTED ATTACKS: {attack_count:,} ({(attack_count/total_count)*100:.2f}%)")
print(f"DETECTED BENIGN:  {benign_count:,} ({(benign_count/total_count)*100:.2f}%)")
print("#" * 60)

# ============================================================================
# 5. SAVING RESULTS
# ============================================================================
print("\n" + "=" * 60)
print("SAVING RESULTS")
print("=" * 60)

# Add predictions to dataframe
output_df = df_test.copy()
output_df['predicted_prob'] = y_prob
output_df['predicted_label'] = y_pred
output_df['predicted_class'] = ['ATTACK' if x == 1 else 'BENIGN' for x in y_pred]

try:
    output_df.to_csv(OUTPUT_FILE, index=False)
    print(f"[OK] Predictions saved to: {OUTPUT_FILE}")
except Exception as e:
    print(f"[ERROR] Failed to save predictions: {e}")

print("\nDone.")
