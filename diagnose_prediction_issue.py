"""
Diagnostic Script: Investigate Why Model Predicts All Attacks

This script helps identify why the LightGBM model is misclassifying benign traffic
"""

import pandas as pd
import numpy as np
import pickle

print("=" * 80)
print("DIAGNOSTIC: LightGBM Model Prediction Issue")
print("=" * 80)

# Load the test data
test_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\benign_generated_mix.csv'
print(f"\n1. Loading test data: {test_file}")
df = pd.read_csv(test_file)
print(f"   Shape: {df.shape}")
print(f"   Columns: {list(df.columns)}")

# Check for label column
if 'label' in df.columns:
    print(f"\n   Labels found: {df['label'].value_counts().to_dict()}")
else:
    print(f"\n   [!] No label column found!")

# Check NaN values BEFORE preprocessing
print("\n2. Checking for NaN values BEFORE preprocessing:")
nan_counts = df.isnull().sum()
cols_with_nan = nan_counts[nan_counts > 0]
if len(cols_with_nan) > 0:
    print(f"   Found {len(cols_with_nan)} columns with NaN:")
    for col, count in cols_with_nan.items():
        print(f"      - {col}: {count} NaN values ({count/len(df)*100:.1f}%)")
else:
    print("   No NaN values found")

# Check key DNS features
print("\n3. Analyzing key DNS features (first 5 rows):")
dns_features = [
    'dns_amplification_factor',
    'query_response_ratio', 
    'dns_any_query_ratio',
    'dns_txt_query_ratio',
    'dns_queries_per_second',
    'dns_total_queries',
    'dns_total_responses'
]

for feat in dns_features:
    if feat in df.columns:
        values = df[feat].head()
        print(f"   {feat}: {list(values)}")
        print(f"      Mean: {df[feat].mean():.4f}, Median: {df[feat].median():.4f}, "
              f"Min: {df[feat].min():.4f}, Max: {df[feat].max():.4f}")
    else:
        print(f"   ⚠ {feat}: MISSING!")

# After preprocessing simulation
print("\n4. Simulating preprocessing (fillna with 0):")
df_processed = df.copy()
df_processed.replace([np.inf, -np.inf], np.nan, inplace=True)
df_processed.fillna(0, inplace=True)

# Drop identity columns
columns_to_drop = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'label']
df_processed = df_processed.drop(columns=[c for c in columns_to_drop if c in df_processed.columns], errors='ignore')

print(f"   After preprocessing shape: {df_processed.shape}")

# Check if all values are zeros (would indicate attack pattern)
print("\n5. Checking for zero-dominated features:")
zero_dominated = []
for col in df_processed.columns:
    zero_pct = (df_processed[col] == 0).sum() / len(df_processed) * 100
    if zero_pct > 80:
        zero_dominated.append((col, zero_pct))

if zero_dominated:
    print(f"   Found {len(zero_dominated)} features with >80% zeros:")
    for col, pct in sorted(zero_dominated, key=lambda x: x[1], reverse=True)[:10]:
        print(f"      - {col}: {pct:.1f}% zeros")
else:
    print("   No zero-dominated features found")

# Statistical summary
print("\n6. Feature statistics summary:")
print(df_processed.describe().T[['mean', 'std', 'min', 'max']].head(10))

# Compare with training data statistics (if available)
print("\n7. Comparing with training data:")
training_file = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset\final_balanced_dataset.csv'
try:
    print(f"   Loading training data sample...")
    df_train = pd.read_csv(training_file, nrows=1000)
    
    # Get benign samples only
    if 'label' in df_train.columns:
        df_train_benign = df_train[df_train['label'] == 0]
        print(f"   Found {len(df_train_benign)} benign samples in training data")
        
        # Compare key features
        print("\n   Comparing key features (Training Benign vs Test Data):")
        compare_features = ['dns_amplification_factor', 'query_response_ratio', 
                          'dns_queries_per_second', 'flow_bytes_per_sec']
        
        for feat in compare_features:
            if feat in df_train_benign.columns and feat in df.columns:
                train_mean = df_train_benign[feat].mean()
                test_mean = df[feat].mean()
                print(f"      {feat}:")
                print(f"         Training (benign): {train_mean:.4f}")
                print(f"         Test data:         {test_mean:.4f}")
                print(f"         Difference:        {abs(train_mean - test_mean):.4f}")
    
except FileNotFoundError:
    print("   ⚠ Training data file not found - skipping comparison")
except Exception as e:
    print(f"   ⚠ Error loading training data: {e}")

# Check protocol distribution
print("\n8. Protocol distribution:")
if 'protocol' in df.columns:
    print(df['protocol'].value_counts())
else:
    print("   ⚠ Protocol column not found!")

print("\n" + "=" * 80)
print("DIAGNOSTIC COMPLETE")
print("=" * 80)

print("\n🔍 LIKELY ISSUES:")
print("   1. If many DNS features are NaN → They become 0 → Looks like attack")
print("   2. If DNS features are missing entirely → Model sees unusual pattern")
print("   3. If feature distributions differ from training → Out of distribution")
print("   4. If protocol values differ → Categorical mismatch")
print("\n💡 RECOMMENDATIONS:")
print("   - Check if benign traffic generator created proper DNS features")
print("   - Verify DNS features are populated (not 0 or NaN)")
print("   - Compare test data format with training data format")
print("   - Run generate_normal_dns.py to ensure realistic benign patterns")
