"""
Step 2: Merge all benign files and encode label as 0
"""
import pandas as pd
import os

# Paths
benign_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\New folder'
output_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset'

# Create output directory
os.makedirs(output_dir, exist_ok=True)

# Benign files to merge
benign_files = [
    'benign_traffic_1_fixed.csv',
    'benign_traffic_2_fixed.csv',
    'benign_traffic_3_fixed.csv',
    'benign_traffic_CICBellDNS2021_1.csv',
    'benign_traffic_CICBellEXFDNS2021_1.csv',
    'benign_traffic_CICBellEXFDNS2021_2.csv',
    'benign_traffic_fixed.csv'
]

print("=" * 60)
print("STEP 2: Merging Benign Files")
print("=" * 60)

benign_dfs = []
for file in benign_files:
    filepath = os.path.join(benign_dir, file)
    if os.path.exists(filepath):
        df = pd.read_csv(filepath)
        print(f"✓ {file}: {len(df):,} rows")
        benign_dfs.append(df)
    else:
        print(f"✗ {file}: NOT FOUND")

# Combine all benign
all_benign = pd.concat(benign_dfs, ignore_index=True)
print(f"\nTotal benign rows: {len(all_benign):,}")

# Encode label: BENIGN = 0
all_benign['label'] = all_benign['label'].apply(lambda x: 0)
print("✓ Encoded labels: BENIGN = 0")

# Shuffle
all_benign = all_benign.sample(frac=1, random_state=42).reset_index(drop=True)
print("✓ Shuffled benign data")

# Save
output_path = os.path.join(output_dir, 'all_benign_encoded.csv')
all_benign.to_csv(output_path, index=False)
print(f"\nSaved: {output_path}")
print(f"Final benign rows: {len(all_benign):,}")
print("=" * 60)
