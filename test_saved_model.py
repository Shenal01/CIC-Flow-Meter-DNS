"""
Test Script for Saved XGBoost DNS Abuse Detection Model

This script demonstrates how to:
1. Load the saved model (pickle or JSON format)
2. Preprocess new data
3. Make predictions
4. Validate model performance

Author: Cybersecurity Data Science Team
"""

import pandas as pd
import numpy as np
import pickle
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, recall_score
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

# Model file (change based on what you saved)
MODEL_FILE = 'xgboost_dns_abuse_infrastructure_model.pkl'  # or .json
MODEL_FORMAT = 'pkl'  # Options: 'pkl' or 'json'

# Test data file (can be a subset of your original dataset or new data)
TEST_DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\generated_benign_shenal.csv'

# Number of samples to test (set to None to test all)
NUM_SAMPLES = 1000  # Test on 1000 random samples

# ============================================================================
# STEP 1: LOAD THE SAVED MODEL
# ============================================================================

print("=" * 80)
print("LOADING SAVED MODEL")
print("=" * 80)

if MODEL_FORMAT == 'pkl':
    # Load pickle model
    print(f"\nLoading model from: {MODEL_FILE}")
    with open(MODEL_FILE, 'rb') as f:
        model = pickle.load(f)
    print("[OK] Model loaded successfully from Pickle file")
    
elif MODEL_FORMAT == 'json':
    # Load JSON model
    print(f"\nLoading model from: {MODEL_FILE}")
    model = xgb.XGBClassifier()
    model.load_model(MODEL_FILE)
    print("[OK] Model loaded successfully from JSON file")
    
else:
    raise ValueError("MODEL_FORMAT must be 'pkl' or 'json'")

print(f"\nModel Info:")
print(f"  - Type: {type(model).__name__}")
print(f"  - Number of features expected: {model.n_features_in_}")

# ============================================================================
# STEP 2: LOAD AND PREPROCESS TEST DATA
# ============================================================================

print("\n" + "=" * 80)
print("LOADING TEST DATA")
print("=" * 80)

# Load test data
print(f"\nLoading data from: {TEST_DATA_PATH}")
df_test = pd.read_csv(TEST_DATA_PATH)

# Sample random rows if NUM_SAMPLES is set
if NUM_SAMPLES and NUM_SAMPLES < len(df_test):
    df_test = df_test.sample(n=NUM_SAMPLES, random_state=42)
    print(f"[OK] Sampled {NUM_SAMPLES:,} random rows for testing")
else:
    print(f"[OK] Using all {len(df_test):,} rows for testing")

print(f"\nTest data shape: {df_test.shape}")
print(f"Columns: {len(df_test.columns)}")

# ============================================================================
# STEP 3: PREPROCESS DATA (SAME AS TRAINING)
# ============================================================================

print("\n" + "=" * 80)
print("PREPROCESSING TEST DATA")
print("=" * 80)

print("\n1. Handling infinite and NaN values...")
df_test.replace([np.inf, -np.inf], np.nan, inplace=True)
df_test.fillna(0, inplace=True)
print("   [OK] Infinite/NaN values handled")

print("\n2. Dropping identity columns...")
columns_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
existing_cols_to_drop = [col for col in columns_to_drop if col in df_test.columns]
df_test_clean = df_test.drop(columns=existing_cols_to_drop, errors='ignore')
print(f"   [OK] Dropped {len(existing_cols_to_drop)} columns: {existing_cols_to_drop}")

print("\n3. Encoding categorical features...")
if 'protocol' in df_test_clean.columns:
    protocol_encoder = LabelEncoder()
    df_test_clean['protocol'] = protocol_encoder.fit_transform(df_test_clean['protocol'])
    print(f"   [OK] Protocol encoded: {list(protocol_encoder.classes_)}")

# Separate features and labels
if 'label' in df_test_clean.columns:
    X_test = df_test_clean.drop('label', axis=1)
    y_test = df_test_clean['label']
    has_labels = True
    print(f"\n[OK] Preprocessing complete")
    print(f"   - Features shape: {X_test.shape}")
    print(f"   - Labels shape: {y_test.shape}")
else:
    # No labels in test data (truly new unseen data)
    X_test = df_test_clean
    y_test = None
    has_labels = False
    print(f"\n[OK] Preprocessing complete")
    print(f"   - Features shape: {X_test.shape}")
    print(f"   - No labels found (unlabeled data)")

# Verify feature count matches model expectations
if X_test.shape[1] != model.n_features_in_:
    print(f"\n⚠ WARNING: Feature count mismatch!")
    print(f"   Model expects: {model.n_features_in_} features")
    print(f"   Data has: {X_test.shape[1]} features")
    print(f"\n   This may cause prediction errors!")
else:
    print(f"\n[OK] Feature count matches model expectations ({model.n_features_in_} features)")

# ============================================================================
# STEP 4: MAKE PREDICTIONS
# ============================================================================

print("\n" + "=" * 80)
print("MAKING PREDICTIONS")
print("=" * 80)

print("\nGenerating predictions...")
y_pred = model.predict(X_test)
y_pred_proba = model.predict_proba(X_test)

print("[OK] Predictions generated")
print(f"\nPrediction distribution:")
unique, counts = np.unique(y_pred, return_counts=True)
for label, count in zip(unique, counts):
    label_name = 'BENIGN' if label == 0 else 'ATTACK'
    percentage = (count / len(y_pred)) * 100
    print(f"  - {label_name} ({label}): {count:,} ({percentage:.2f}%)")

# ============================================================================
# STEP 5: DISPLAY SAMPLE PREDICTIONS
# ============================================================================

print("\n" + "=" * 80)
print("SAMPLE PREDICTIONS")
print("=" * 80)

# Show first 10 predictions
print("\nFirst 10 predictions:")
print(f"{'Index':<8} {'Actual':<10} {'Predicted':<12} {'Prob(BENIGN)':<15} {'Prob(ATTACK)':<15}")
print("-" * 70)

for i in range(min(10, len(y_pred))):
    if has_labels:
        actual = 'BENIGN' if y_test.iloc[i] == 0 else 'ATTACK'
    else:
        actual = 'N/A'
    
    predicted = 'BENIGN' if y_pred[i] == 0 else 'ATTACK'
    prob_benign = y_pred_proba[i][0]
    prob_attack = y_pred_proba[i][1]
    
    print(f"{i:<8} {actual:<10} {predicted:<12} {prob_benign:<15.4f} {prob_attack:<15.4f}")

# ============================================================================
# STEP 6: EVALUATE MODEL PERFORMANCE (if labels available)
# ============================================================================

if has_labels:
    print("\n" + "=" * 80)
    print("MODEL PERFORMANCE EVALUATION")
    print("=" * 80)
    
    # Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Confusion Matrix
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    tn, fp, fn, tp = cm.ravel()
    print(f"\nBreakdown:")
    print(f"  True Negatives (TN):  {tn:,}")
    print(f"  False Positives (FP): {fp:,}")
    print(f"  False Negatives (FN): {fn:,}")
    print(f"  True Positives (TP):  {tp:,}")
    
    # Classification Report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['BENIGN', 'ATTACK'],
                                digits=4))
    
    # Recall scores
    recall_benign = recall_score(y_test, y_pred, pos_label=0)
    recall_attack = recall_score(y_test, y_pred, pos_label=1)
    recall_macro = recall_score(y_test, y_pred, average='macro')
    
    print(f"\nRecall Scores:")
    print(f"  BENIGN: {recall_benign:.4f} ({recall_benign*100:.2f}%)")
    print(f"  ATTACK: {recall_attack:.4f} ({recall_attack*100:.2f}%)")
    print(f"  Macro Average: {recall_macro:.4f} ({recall_macro*100:.2f}%)")
    
    # Additional metrics
    from sklearn.metrics import roc_auc_score
    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
    print(f"\nROC-AUC Score: {roc_auc:.4f}")
    
else:
    print("\n" + "=" * 80)
    print("NO LABELS AVAILABLE - SKIPPING EVALUATION")
    print("=" * 80)
    print("\nPredictions have been made, but cannot evaluate performance without labels.")

# ============================================================================
# STEP 7: SAVE PREDICTIONS (OPTIONAL)
# ============================================================================

print("\n" + "=" * 80)
print("SAVING PREDICTIONS (Optional)")
print("=" * 80)

SAVE_PREDICTIONS = True  # Set to False to skip saving

if SAVE_PREDICTIONS:
    # Create predictions DataFrame
    predictions_df = pd.DataFrame({
        'prediction': y_pred,
        'prob_benign': y_pred_proba[:, 0],
        'prob_attack': y_pred_proba[:, 1],
        'prediction_label': ['BENIGN' if p == 0 else 'ATTACK' for p in y_pred]
    })
    
    if has_labels:
        predictions_df['actual'] = y_test.values
        predictions_df['actual_label'] = ['BENIGN' if a == 0 else 'ATTACK' for a in y_test]
        predictions_df['correct'] = (y_test.values == y_pred)
    
    # Save to CSV
    output_file = 'model_predictions.csv'
    predictions_df.to_csv(output_file, index=False)
    print(f"\n[OK] Predictions saved to: {output_file}")
    print(f"   Rows: {len(predictions_df):,}")
else:
    print("\n[SKIP] Prediction saving skipped")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("TESTING COMPLETE")
print("=" * 80)

print("\n[OK] Model testing finished successfully!")
print(f"\nSummary:")
print(f"  - Model loaded: {MODEL_FILE}")
print(f"  - Samples tested: {len(y_pred):,}")

# Handle cases where all predictions might be of a single class
benign_count = counts[0] if unique[0] == 0 else (counts[1] if len(counts) > 1 and unique[1] == 0 else 0)
attack_count = counts[0] if unique[0] == 1 else (counts[1] if len(counts) > 1 and unique[1] == 1 else 0)
print(f"  - Predictions: {benign_count:,} BENIGN, {attack_count:,} ATTACK")

if has_labels:
    print(f"  - Accuracy: {accuracy*100:.2f}%")
    print(f"  - Recall (BENIGN): {recall_benign*100:.2f}%")
    print(f"  - Recall (ATTACK): {recall_attack*100:.2f}%")
    print(f"  - Recall (Macro Avg): {recall_macro*100:.2f}%")
    print(f"  - ROC-AUC: {roc_auc:.4f}")

print("\n" + "=" * 80)

