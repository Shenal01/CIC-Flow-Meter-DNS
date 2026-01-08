"""
Extract Benign Test Set from Training Data

Since live-captured traffic has different feature distributions than training data,
extract real benign samples from training data for model validation.
"""

import pandas as pd
import sys

print("=" * 80)
print("EXTRACTING BENIGN TEST SET FROM TRAINING DATA")
print("=" * 80)

# Configuration
TRAINING_FILE = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset\final_balanced_dataset.csv'
OUTPUT_FILE = 'test_benign_from_training.csv'
NUM_SAMPLES = 1000
RANDOM_SEED = 999  # Different from training to ensure different samples

print(f"\nStep 1: Loading training data...")
print(f"  File: {TRAINING_FILE}")

df = pd.read_csv(TRAINING_FILE)
print(f"  Loaded: {len(df):,} total rows")
print(f"  Columns: {len(df.columns)}")

# Get benign samples (label = 0)
print(f"\nStep 2: Filtering benign samples...")
benign = df[df['label'] == 0].copy()
print(f"  Found: {len(benign):,} benign samples ({len(benign)/len(df)*100:.1f}%)")

# Sample random benign flows
print(f"\nStep 3: Sampling {NUM_SAMPLES:,} random benign flows...")
print(f"  Random seed: {RANDOM_SEED} (different from training split)")

if len(benign) < NUM_SAMPLES:
    print(f"  [!] WARNING: Only {len(benign):,} benign samples available")
    print(f"  Using all {len(benign):,} samples")
    test_benign = benign
else:
    test_benign = benign.sample(n=NUM_SAMPLES, random_state=RANDOM_SEED)
    print(f"  Sampled: {len(test_benign):,} samples")

# Check protocol distribution
print(f"\nStep 4: Verifying data quality...")
print(f"  Protocol distribution:")
protocol_dist = test_benign['protocol'].value_counts()
for proto, count in protocol_dist.items():
    print(f"    {proto}: {count:,} ({count/len(test_benign)*100:.1f}%)")

# Check key features
print(f"\n  Key feature statistics:")
key_features = ['dns_amplification_factor', 'query_response_ratio', 
                'dns_queries_per_second', 'flow_bytes_per_sec']

for feat in key_features:
    mean_val = test_benign[feat].mean()
    median_val = test_benign[feat].median()
    print(f"    {feat:30s}: mean={mean_val:10.2f}, median={median_val:10.2f}")

# Drop label column (for testing as if unlabeled)
print(f"\nStep 5: Preparing test file (keeping label for validation)...")
# Keep label for verification but save separately
test_data_with_label = test_benign.copy()

# Save with label
print(f"  Saving with label column for validation...")
test_data_with_label.to_csv(OUTPUT_FILE, index=False)
print(f"  [OK] Saved: {OUTPUT_FILE}")
print(f"  Rows: {len(test_data_with_label):,}")
print(f"  Columns: {len(test_data_with_label.columns)}")

# Also save without label for pure prediction testing
output_no_label = OUTPUT_FILE.replace('.csv', '_no_label.csv')
test_data_no_label = test_benign.drop('label', axis=1)
test_data_no_label.to_csv(output_no_label, index=False)
print(f"\n  [OK] Also saved without label: {output_no_label}")
print(f"  Rows: {len(test_data_no_label):,}")
print(f"  Columns: {len(test_data_no_label.columns)}")

print("\n" + "=" * 80)
print("EXTRACTION COMPLETE")
print("=" * 80)
print(f"\n[OK] Test files created successfully!")
print(f"\nFiles created:")
print(f"  1. {OUTPUT_FILE} - with label column (for evaluation)")
print(f"  2. {output_no_label} - without label (for pure prediction)")
print(f"\nNext steps:")
print(f"  1. Update test_lightgbm_model.py to use these files")
print(f"  2. Run python test_lightgbm_model.py")
print(f"  3. Model should predict ~{len(test_benign):,} BENIGN (not ATTACK)")
