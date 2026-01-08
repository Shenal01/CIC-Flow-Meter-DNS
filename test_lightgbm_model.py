"""
Test Script for Saved LightGBM DNS Abuse Detection Model

This script demonstrates how to:
1. Load the saved LightGBM model and feature info
2. Preprocess new data
3. Make predictions
4. Validate model performance on different attack types

Author: Cybersecurity Data Science Team
Component: AI/ML Detection of DNS Abuse and Infrastructure Attacks
"""

import pandas as pd
import numpy as np
import pickle
import lightgbm as lgb
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score
)
import warnings
import os
from datetime import datetime

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

# Model files
MODEL_FILE = 'lightgbm_dns_infrastructure_model.pkl'
FEATURE_INFO_FILE = 'lightgbm_feature_info.pkl'

# Test data paths - Update these to your actual test files
TEST_DATA_PATHS = {
    'benign_from_training': 'test_benign_from_training.csv',  # Benign samples from training data
    'realistic_generated': 'realistic_benign_traffic.csv',  # NEW: Synthetic realistic benign
    'live_captured_traffic': r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\generated_mix_google_sheet_demo.csv',  # Live captured
    # Add more test files as needed:
    # 'dns_amplification': r'C:\path\to\dns_amplification_attacks.csv',
    # 'dns_tunneling': r'C:\path\to\dns_tunneling_attacks.csv',
}

# Number of samples to test (set to None to test all)
NUM_SAMPLES = None  # Test all samples

# ============================================================================
# UTILITIES
# ============================================================================

def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

def print_subsection(title):
    """Print formatted subsection header"""
    print(f"\n{title}")
    print("-" * 80)

# ============================================================================
# STEP 1: LOAD THE SAVED MODEL AND FEATURE INFO
# ============================================================================

print_section("LOADING SAVED LIGHTGBM MODEL")

# Load the model
print(f"\nLoading model from: {MODEL_FILE}")
if not os.path.exists(MODEL_FILE):
    raise FileNotFoundError(f"Model file not found: {MODEL_FILE}")

with open(MODEL_FILE, 'rb') as f:
    model = pickle.load(f)

print("[OK] Model loaded successfully")
print(f"\nModel Info:")
print(f"  - Type: {type(model).__name__}")
print(f"  - Number of trees: {model.num_trees()}")

# Load feature information
if os.path.exists(FEATURE_INFO_FILE):
    print(f"\nLoading feature info from: {FEATURE_INFO_FILE}")
    with open(FEATURE_INFO_FILE, 'rb') as f:
        feature_info = pickle.load(f)
    
    feature_names = feature_info['feature_names']
    categorical_features = feature_info['categorical_features']
    best_iteration = feature_info.get('best_iteration', None)
    
    print("[OK] Feature information loaded successfully")
    print(f"  - Number of features: {len(feature_names)}")
    print(f"  - Categorical features: {categorical_features}")
    if best_iteration:
        print(f"  - Best iteration: {best_iteration}")
else:
    print("\n[!] WARNING: Feature info file not found. Using model's feature names.")
    feature_names = model.feature_name()
    categorical_features = []

print(f"\nExpected features ({len(feature_names)}):")
for i, fname in enumerate(feature_names, 1):
    print(f"  {i:2d}. {fname}")

# ============================================================================
# STEP 2: DEFINE PREPROCESSING FUNCTION
# ============================================================================

def preprocess_data(df, feature_names, categorical_features):
    """
    Preprocess data to match training pipeline
    
    Args:
        df: Input DataFrame
        feature_names: List of expected feature names
        categorical_features: List of categorical feature names
    
    Returns:
        X: Preprocessed features
        y: Labels (if available)
        has_labels: Boolean indicating if labels exist
    """
    print_subsection("PREPROCESSING DATA")
    
    df_work = df.copy()
    
    # 1. Handle infinite and NaN values
    print("\n1. Handling infinite and NaN values...")
    inf_count = np.isinf(df_work.select_dtypes(include=[np.number])).sum().sum()
    nan_count = df_work.isnull().sum().sum()
    print(f"   - Found {inf_count:,} infinite values")
    print(f"   - Found {nan_count:,} NaN values")
    
    df_work.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_work.fillna(0, inplace=True)
    print("   [OK] Infinite/NaN values handled")
    
    # 2. Drop identity columns
    print("\n2. Dropping identity columns...")
    columns_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
    existing_cols_to_drop = [col for col in columns_to_drop if col in df_work.columns]
    df_work = df_work.drop(columns=existing_cols_to_drop, errors='ignore')
    print(f"   [OK] Dropped {len(existing_cols_to_drop)} columns: {existing_cols_to_drop}")
    
    # 3. Handle categorical features (LightGBM native support)
    print("\n3. Converting categorical features...")
    for cat_feat in categorical_features:
        if cat_feat in df_work.columns:
            df_work[cat_feat] = df_work[cat_feat].astype('category')
            print(f"   [OK] Converted '{cat_feat}' to category")
    
    # 4. Separate features and labels
    if 'label' in df_work.columns:
        X = df_work.drop('label', axis=1)
        y = df_work['label']
        has_labels = True
        print(f"\n[OK] Preprocessing complete")
        print(f"   - Features shape: {X.shape}")
        print(f"   - Labels shape: {y.shape}")
        print(f"   - Label distribution: {dict(y.value_counts())}")
    else:
        X = df_work
        y = None
        has_labels = False
        print(f"\n[OK] Preprocessing complete")
        print(f"   - Features shape: {X.shape}")
        print(f"   - No labels found (unlabeled data)")
    
    # 5. Verify feature alignment
    print("\n4. Verifying feature alignment...")
    missing_features = set(feature_names) - set(X.columns)
    extra_features = set(X.columns) - set(feature_names)
    
    if missing_features:
        print(f"   [!] WARNING: Missing features: {missing_features}")
        # Add missing features with zeros
        for feat in missing_features:
            X[feat] = 0
        print(f"   [OK] Added missing features with default value 0")
    
    if extra_features:
        print(f"   [!] WARNING: Extra features found: {extra_features}")
        X = X.drop(columns=list(extra_features))
        print(f"   [OK] Dropped extra features")
    
    # Reorder columns to match training order
    X = X[feature_names]
    print(f"   [OK] Feature alignment verified ({len(feature_names)} features)")
    
    return X, y, has_labels

# ============================================================================
# STEP 3: MAKE PREDICTIONS FUNCTION
# ============================================================================

def make_predictions(model, X, use_best_iteration=True):
    """
    Make predictions using the LightGBM model
    
    Args:
        model: Trained LightGBM model
        X: Feature matrix
        use_best_iteration: Whether to use best iteration from training
    
    Returns:
        y_pred: Binary predictions (0/1)
        y_pred_proba: Probability predictions
    """
    print_subsection("MAKING PREDICTIONS")
    
    print("\nGenerating predictions...")
    
    # Get probabilities
    if use_best_iteration and hasattr(model, 'best_iteration') and model.best_iteration > 0:
        y_pred_proba = model.predict(X, num_iteration=model.best_iteration)
        print(f"   Using best iteration: {model.best_iteration}")
    else:
        y_pred_proba = model.predict(X)
        print(f"   Using all trees: {model.num_trees()}")
    
    # Convert probabilities to binary predictions
    y_pred = (y_pred_proba >= 0.5).astype(int)
    
    print("[OK] Predictions generated")
    
    # Show prediction distribution
    unique, counts = np.unique(y_pred, return_counts=True)
    print(f"\nPrediction distribution:")
    for label, count in zip(unique, counts):
        label_name = 'BENIGN' if label == 0 else 'ATTACK'
        percentage = (count / len(y_pred)) * 100
        print(f"  - {label_name} ({label}): {count:,} ({percentage:.2f}%)")
    
    return y_pred, y_pred_proba

# ============================================================================
# STEP 4: EVALUATE PERFORMANCE FUNCTION
# ============================================================================

def evaluate_performance(y_true, y_pred, y_pred_proba):
    """
    Evaluate model performance with comprehensive metrics
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        y_pred_proba: Predicted probabilities
    """
    print_section("MODEL PERFORMANCE EVALUATION")
    
    # Basic metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    print(f"\n{'Metric':<20} {'Score':<10}")
    print("-" * 30)
    print(f"{'Accuracy':<20} {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"{'Precision':<20} {precision:.4f}")
    print(f"{'Recall (TPR)':<20} {recall:.4f}")
    print(f"{'F1-Score':<20} {f1:.4f}")
    
    # ROC-AUC (if both classes present)
    if len(np.unique(y_true)) > 1:
        roc_auc = roc_auc_score(y_true, y_pred_proba)
        print(f"{'ROC-AUC':<20} {roc_auc:.4f}")
    
    # Confusion Matrix
    print_subsection("CONFUSION MATRIX")
    cm = confusion_matrix(y_true, y_pred)
    
    print(f"\n                 Predicted")
    print(f"               BENIGN  ATTACK")
    print(f"Actual BENIGN  {cm[0,0]:6,}  {cm[0,1]:6,}")
    print(f"       ATTACK  {cm[1,0]:6,}  {cm[1,1]:6,}")
    
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\nDetailed Breakdown:")
    print(f"  True Negatives (TN):  {tn:>8,} - Correctly identified BENIGN")
    print(f"  False Positives (FP): {fp:>8,} - BENIGN incorrectly flagged as ATTACK")
    print(f"  False Negatives (FN): {fn:>8,} - ATTACK incorrectly flagged as BENIGN")
    print(f"  True Positives (TP):  {tp:>8,} - Correctly identified ATTACK")
    
    # Additional derived metrics
    print(f"\nDerived Metrics:")
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"  Specificity (TNR):    {specificity:.4f} - True Negative Rate")
    print(f"  False Positive Rate:  {fpr:.4f} - Benign flagged as attack")
    print(f"  False Negative Rate:  {fnr:.4f} - Attacks missed")
    
    # Classification Report
    print_subsection("CLASSIFICATION REPORT")
    print("\n" + classification_report(y_true, y_pred, 
                                      target_names=['BENIGN', 'ATTACK'],
                                      digits=4))
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc if len(np.unique(y_true)) > 1 else None,
        'confusion_matrix': cm
    }

# ============================================================================
# STEP 5: DISPLAY SAMPLE PREDICTIONS
# ============================================================================

def show_sample_predictions(y_true, y_pred, y_pred_proba, num_samples=20):
    """Display sample predictions for inspection"""
    print_subsection("SAMPLE PREDICTIONS")
    
    print(f"\nShowing first {num_samples} predictions:")
    print(f"{'Index':<8} {'Actual':<10} {'Predicted':<12} {'Prob(BENIGN)':<15} {'Prob(ATTACK)':<15} {'Correct':<10}")
    print("-" * 80)
    
    for i in range(min(num_samples, len(y_pred))):
        if y_true is not None:
            actual = 'BENIGN' if y_true.iloc[i] == 0 else 'ATTACK'
            correct = '[OK]' if y_true.iloc[i] == y_pred[i] else '✗ WRONG'
        else:
            actual = 'N/A'
            correct = 'N/A'
        
        predicted = 'BENIGN' if y_pred[i] == 0 else 'ATTACK'
        prob_benign = 1 - y_pred_proba[i]
        prob_attack = y_pred_proba[i]
        
        print(f"{i:<8} {actual:<10} {predicted:<12} {prob_benign:<15.4f} {prob_attack:<15.4f} {correct:<10}")

# ============================================================================
# STEP 6: SAVE PREDICTIONS (OPTIONAL)
# ============================================================================

def save_predictions(y_pred, y_pred_proba, y_true=None, output_file='lightgbm_predictions.csv'):
    """Save predictions to CSV file"""
    print_subsection("SAVING PREDICTIONS")
    
    # Create predictions DataFrame
    predictions_df = pd.DataFrame({
        'prediction': y_pred,
        'prob_benign': 1 - y_pred_proba,
        'prob_attack': y_pred_proba,
        'prediction_label': ['BENIGN' if p == 0 else 'ATTACK' for p in y_pred],
        'confidence': np.maximum(y_pred_proba, 1 - y_pred_proba)
    })
    
    if y_true is not None:
        predictions_df['actual'] = y_true.values
        predictions_df['actual_label'] = ['BENIGN' if a == 0 else 'ATTACK' for a in y_true]
        predictions_df['correct'] = (y_true.values == y_pred)
    
    # Save to CSV
    predictions_df.to_csv(output_file, index=False)
    print(f"\n[OK] Predictions saved to: {output_file}")
    print(f"   Rows: {len(predictions_df):,}")
    
    # Show confidence distribution
    print(f"\nConfidence Distribution:")
    print(f"  High confidence (>0.9):   {(predictions_df['confidence'] > 0.9).sum():,}")
    print(f"  Medium confidence (0.7-0.9): {((predictions_df['confidence'] >= 0.7) & (predictions_df['confidence'] <= 0.9)).sum():,}")
    print(f"  Low confidence (<0.7):    {(predictions_df['confidence'] < 0.7).sum():,}")

# ============================================================================
# MAIN TESTING WORKFLOW
# ============================================================================

def test_model_on_file(test_file_path, test_name="Test"):
    """Test the model on a specific file"""
    print_section(f"TESTING ON: {test_name}")
    
    # Check if file exists
    if not os.path.exists(test_file_path):
        print(f"\n[!] WARNING: Test file not found: {test_file_path}")
        print("   Skipping this test...")
        return None
    
    # Load test data
    print(f"\nLoading data from: {test_file_path}")
    df_test = pd.read_csv(test_file_path)
    
    # Sample if needed
    if NUM_SAMPLES and NUM_SAMPLES < len(df_test):
        df_test = df_test.sample(n=NUM_SAMPLES, random_state=42)
        print(f"[OK] Sampled {NUM_SAMPLES:,} random rows for testing")
    else:
        print(f"[OK] Using all {len(df_test):,} rows for testing")
    
    print(f"   Shape: {df_test.shape}")
    
    # Preprocess data
    X_test, y_test, has_labels = preprocess_data(df_test, feature_names, categorical_features)
    
    # Make predictions
    y_pred, y_pred_proba = make_predictions(model, X_test)
    
    # Show sample predictions
    show_sample_predictions(y_test, y_pred, y_pred_proba, num_samples=10)
    
    # Evaluate if labels available
    results = None
    if has_labels:
        results = evaluate_performance(y_test, y_pred, y_pred_proba)
    else:
        print("\n[!] No labels available - skipping performance evaluation")
    
    # Save predictions
    output_file = f'predictions_{test_name.lower().replace(" ", "_")}.csv'
    save_predictions(y_pred, y_pred_proba, y_test, output_file)
    
    return results

# ============================================================================
# EXECUTE TESTS
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("LIGHTGBM DNS ABUSE DETECTION MODEL - TESTING SUITE")
    print("=" * 80)
    print(f"\nExecution started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    all_results = {}
    
    # Test on each configured file
    for test_name, test_path in TEST_DATA_PATHS.items():
        result = test_model_on_file(test_path, test_name)
        if result:
            all_results[test_name] = result
    
    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    
    print_section("TESTING COMPLETE - SUMMARY")
    
    print(f"\n[OK] Model testing finished successfully!")
    print(f"\nModel: {MODEL_FILE}")
    print(f"Tests completed: {len(all_results)}")
    
    if all_results:
        print(f"\n{'Test Name':<20} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
        print("-" * 68)
        for test_name, results in all_results.items():
            print(f"{test_name:<20} {results['accuracy']:>10.4f}  {results['precision']:>10.4f}  {results['recall']:>10.4f}  {results['f1']:>10.4f}")
    
    print("\n" + "=" * 80)
    print(f"Execution completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
