"""
LightGBM Model Training Script
DNS Abuse & Infrastructure Attack Detection
"""

# Import required libraries
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix, 
    classification_report, 
    accuracy_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    auc
)
import lightgbm as lgb
from datetime import datetime
import pickle
import time
import os

# Configure display settings
warnings.filterwarnings('ignore')
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', 100)
sns.set_style('whitegrid')
plt.rcParams['figure.figsize'] = (12, 6)

print("="*80)
print("LIGHTGBM MODEL TRAINING - DNS ABUSE & INFRASTRUCTURE ATTACK DETECTION")
print("="*80)
print(f"\n[OK] All libraries imported successfully")
print(f"LightGBM version: {lgb.__version__}")
print(f"Execution started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# ============================================================================
# 1. DATA LOADING
# ============================================================================
DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset\final_balanced_dataset.csv'

print("="*80)
print("LOADING DATASET")
print("="*80)
print(f"\nLoading from: {DATA_PATH}")
df = pd.read_csv(DATA_PATH)
print(f"[OK] Dataset loaded successfully")
print(f"  Shape: {df.shape[0]:,} rows × {df.shape[1]} columns\n")

# ============================================================================
# 2. DATA QUALITY CHECKS
# ============================================================================
print("="*80)
print("DATA QUALITY CHECKS")
print("="*80)

# Check for shuffle
label_changes = (df['label'] != df['label'].shift()).sum()
is_shuffled = label_changes > (len(df) * 0.01)
print(f"\nShuffle check: {'[OK] SHUFFLED' if is_shuffled else '[WARNING] NOT SHUFFLED'}")

# Check for NaN and infinite values
print(f"NaN values before cleaning: {df.isnull().sum().sum():,}")
print(f"Infinite values before cleaning: {np.isinf(df.select_dtypes(include=[np.number])).sum().sum():,}")

# Clean data
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

print(f"[OK] Data cleaned")
print(f"  NaN values after: {df.isnull().sum().sum()}")
print(f"  Infinite values after: {np.isinf(df.select_dtypes(include=[np.number])).sum().sum()}\n")

# ============================================================================
# 3. FEATURE ENGINEERING
# ============================================================================
print("="*80)
print("FEATURE ENGINEERING")
print("="*80)

# Drop identity columns
columns_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
df_clean = df.drop(columns=columns_to_drop, errors='ignore')
print(f"\n[OK] Dropped {len(columns_to_drop)} identity columns")

# Convert protocol to categorical for LightGBM
df_clean['protocol'] = df_clean['protocol'].astype('category')
print(f"[OK] Converted 'protocol' to categorical type")
print(f"  Protocol distribution: {df_clean['protocol'].value_counts().to_dict()}\n")

# Separate features and labels
X = df_clean.drop('label', axis=1)
y = df_clean['label']

print(f"Final feature set: {X.shape[1]} features")
print(f"Target distribution: {y.value_counts().to_dict()}\n")

# ============================================================================
# 4. TRAIN-TEST SPLIT
# ============================================================================
print("="*80)
print("TRAIN-TEST SPLIT (70-30, Stratified)")
print("="*80)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.3, 
    random_state=42, 
    stratify=y
)

print(f"\nTraining set: {X_train.shape[0]:,} samples")
print(f"Testing set: {X_test.shape[0]:,} samples")
print(f"[OK] Stratified split complete\n")

# ============================================================================
# 5. LIGHTGBM MODEL CONFIGURATION
# ============================================================================
print("="*80)
print("LIGHTGBM MODEL CONFIGURATION")
print("="*80)

params = {
    'objective': 'binary',
    'metric': 'binary_logloss',
    'boosting_type': 'gbdt',
    'num_leaves': 31,
    'learning_rate': 0.05,
    'feature_fraction': 0.9,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'max_depth': -1,
    'min_child_samples': 20,
    'reg_alpha': 0.1,
    'reg_lambda': 0.1,
    'verbose': -1,
    'n_jobs': -1
}

print("\nModel Parameters:")
for key, value in params.items():
    print(f"  {key}: {value}")

# Identify categorical features
categorical_features = [col for col in X_train.columns if X_train[col].dtype.name == 'category']
print(f"\nCategorical features: {categorical_features}")

# Create LightGBM datasets
train_data = lgb.Dataset(
    X_train, 
    label=y_train,
    categorical_feature=categorical_features,
    free_raw_data=False
)

test_data = lgb.Dataset(
    X_test, 
    label=y_test,
    reference=train_data,
    categorical_feature=categorical_features,
    free_raw_data=False
)

print(f"[OK] LightGBM datasets created\n")

# ============================================================================
# 6. MODEL TRAINING
# ============================================================================
print("="*80)
print("TRAINING LIGHTGBM MODEL")
print("="*80)

print("\nTraining started...")
start_time = time.time()

# Train with early stopping
model = lgb.train(
    params,
    train_data,
    num_boost_round=1000,
    valid_sets=[train_data, test_data],
    valid_names=['train', 'valid'],
    callbacks=[
        lgb.early_stopping(stopping_rounds=50, verbose=True),
        lgb.log_evaluation(period=100)
    ]
)

training_time = time.time() - start_time

print(f"\n{'='*80}")
print("TRAINING COMPLETE")
print("="*80)
print(f"Training time: {training_time:.2f} seconds")
print(f"Best iteration: {model.best_iteration}")
print(f"Best score: {model.best_score}\n")

# ============================================================================
# 7. MODEL EVALUATION
# ============================================================================
print("="*80)
print("MODEL EVALUATION")
print("="*80)

# Make predictions
y_pred_proba = model.predict(X_test, num_iteration=model.best_iteration)
y_pred = (y_pred_proba >= 0.5).astype(int)

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_pred_proba)

print(f"\n[OK] Predictions generated")
print(f"\nCONFUSION MATRIX:")
cm = confusion_matrix(y_test, y_pred)
print(f"  TN: {cm[0,0]:,}  |  FP: {cm[0,1]:,}")
print(f"  FN: {cm[1,0]:,}  |  TP: {cm[1,1]:,}")

print(f"\nCLASSIFICATION REPORT:")
print(classification_report(y_test, y_pred, 
                           target_names=['BENIGN', 'ATTACK'],
                           digits=4))

print("="*80)
print("SUMMARY METRICS")
print("="*80)
print(f"\nAccuracy:  {accuracy*100:.2f}%")
print(f"ROC-AUC:   {roc_auc:.4f}\n")

# ============================================================================
# 8. FEATURE IMPORTANCE
# ============================================================================
print("="*80)
print("FEATURE IMPORTANCE")
print("="*80)

importance = model.feature_importance(importance_type='gain')
feature_names = model.feature_name()

importance_df = pd.DataFrame({
    'feature': feature_names,
    'importance': importance
}).sort_values('importance', ascending=False)

print("\nTop 20 Most Important Features:")
print(importance_df.head(20).to_string(index=False))
print()

# ============================================================================
# 9. SAVE MODEL
# ============================================================================
print("="*80)
print("SAVING MODEL")
print("="*80)

model_filename = 'lightgbm_dns_infrastructure_model.pkl'

with open(model_filename, 'wb') as f:
    pickle.dump(model, f)

print(f"\n[OK] Model saved as: {model_filename}")
print(f"  File size: {os.path.getsize(model_filename) / (1024*1024):.2f} MB")

# Save feature info
feature_info = {
    'feature_names': feature_names,
    'categorical_features': categorical_features,
    'best_iteration': model.best_iteration
}

with open('lightgbm_feature_info.pkl', 'wb') as f:
    pickle.dump(feature_info, f)

print(f"[OK] Feature info saved as: lightgbm_feature_info.pkl\n")

# ============================================================================
# 10. FINAL SUMMARY
# ============================================================================
print("="*80)
print("TRAINING SUMMARY")
print("="*80)
print(f"\nModel: LightGBM Gradient Boosting")
print(f"Dataset: {df.shape[0]:,} samples, {X.shape[1]} features")
print(f"Training samples: {X_train.shape[0]:,}")
print(f"Testing samples: {X_test.shape[0]:,}")
print(f"\nPerformance:")
print(f"  - Accuracy: {accuracy*100:.2f}%")
print(f"  - ROC-AUC: {roc_auc:.4f}")
print(f"  - Training time: {training_time:.2f} seconds")
print(f"\nModel saved: {model_filename}")
print(f"\n{'='*80}")
print("[OK] LIGHTGBM TRAINING COMPLETE")
print("="*80)
print(f"\nExecution completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
