"""
Step 3: Combine attacks and benign, shuffle thoroughly, and save final dataset
"""
import pandas as pd
import os

# Paths
input_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset'
output_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset'

print("=" * 60)
print("STEP 3: Combining and Shuffling Final Dataset")
print("=" * 60)

# Load encoded files
attacks_path = os.path.join(input_dir, 'all_attacks_encoded.csv')
benign_path = os.path.join(input_dir, 'all_benign_encoded.csv')

print("Loading data...")
attacks = pd.read_csv(attacks_path)
benign = pd.read_csv(benign_path)

print(f"✓ Attack rows: {len(attacks):,} (label=1)")
print(f"✓ Benign rows: {len(benign):,} (label=0)")

# Combine
print("\nCombining datasets...")
final_dataset = pd.concat([attacks, benign], ignore_index=True)
print(f"✓ Combined rows: {len(final_dataset):,}")

# Shuffle thoroughly (multiple shuffles for good mixing)
print("\nShuffling dataset (3 rounds for thorough mixing)...")
final_dataset = final_dataset.sample(frac=1, random_state=42).reset_index(drop=True)
final_dataset = final_dataset.sample(frac=1, random_state=123).reset_index(drop=True)
final_dataset = final_dataset.sample(frac=1, random_state=999).reset_index(drop=True)
print("✓ Dataset shuffled thoroughly")

# Verify balance
print("\n" + "=" * 60)
print("FINAL DATASET STATISTICS")
print("=" * 60)
print(f"Total rows: {len(final_dataset):,}")
print(f"\nLabel distribution:")
label_counts = final_dataset['label'].value_counts().sort_index()
for label, count in label_counts.items():
    label_name = "BENIGN" if label == 0 else "ATTACK"
    percentage = (count / len(final_dataset)) * 100
    print(f"  {label} ({label_name}): {count:,} rows ({percentage:.2f}%)")

ratio = label_counts[1] / label_counts[0]
print(f"\nAttack:Benign ratio: {ratio:.2f}:1")

# Save final dataset
output_path = os.path.join(output_dir, 'final_balanced_dataset.csv')
final_dataset.to_csv(output_path, index=False)
print(f"\n✓ Saved: {output_path}")

print("\n" + "=" * 60)
print("DATASET READY FOR TRAINING!")
print("=" * 60)
print(f"Location: {output_dir}")
print("Files created:")
print("  1. all_attacks_encoded.csv (intermediate)")
print("  2. all_benign_encoded.csv (intermediate)")
print("  3. final_balanced_dataset.csv (READY TO USE)")
print("=" * 60)
