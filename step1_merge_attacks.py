"""
Step 1: Merge all attack files and encode label as 1
"""
import pandas as pd
import os

# Paths
attack_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\New-CIC-JAVA'
output_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset'

# Create output directory
os.makedirs(output_dir, exist_ok=True)

# Attack files to merge (balanced versions + small attacks)
attack_files = [
    'DDoS_SynonymousIP_Flood_balanced.csv',
    'DDoS_SYN_Flood_balanced.csv',
    'DDoS_TCP_Flood_balanced.csv',
    'DDoS_UDP_Flood_fixed.csv',
    'DNS_Spoofing_fixed.csv',
    'merge_filtered_cic_dns_fixed.csv',
    'Mirai-greeth_flood_fixed.csv',
    'Mirai-greip_flood_fixed.csv'
]

print("=" * 60)
print("STEP 1: Merging Attack Files")
print("=" * 60)

attack_dfs = []
for file in attack_files:
    filepath = os.path.join(attack_dir, file)
    if os.path.exists(filepath):
        df = pd.read_csv(filepath)
        print(f"✓ {file}: {len(df):,} rows")
        attack_dfs.append(df)
    else:
        print(f"✗ {file}: NOT FOUND")

# Combine all attacks
all_attacks = pd.concat(attack_dfs, ignore_index=True)
print(f"\nTotal attack rows: {len(all_attacks):,}")

# Encode label: ATTACK = 1
all_attacks['label'] = all_attacks['label'].apply(lambda x: 1)
print("✓ Encoded labels: ATTACK = 1")

# Shuffle
all_attacks = all_attacks.sample(frac=1, random_state=42).reset_index(drop=True)
print("✓ Shuffled attack data")

# Save
output_path = os.path.join(output_dir, 'all_attacks_encoded.csv')
all_attacks.to_csv(output_path, index=False)
print(f"\nSaved: {output_path}")
print(f"Final attack rows: {len(all_attacks):,}")
print("=" * 60)
