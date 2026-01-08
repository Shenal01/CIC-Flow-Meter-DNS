"""
Analyze Training Data to Establish Benign DNS Traffic Baseline

This script analyzes the training data to understand what realistic benign DNS traffic looks like
"""

import pandas as pd
import numpy as np
import pickle

print("=" * 80)
print("TRAINING DATA ANALYSIS - BENIGN DNS TRAFFIC BASELINE")
print("=" * 80)

# Load training data
TRAINING_FILE = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset\final_balanced_dataset.csv'

print(f"\nLoading training data from: {TRAINING_FILE}")
print("(Loading 10000 samples for analysis...)")

df = pd.read_csv(TRAINING_FILE, nrows=10000)
print(f"Total samples loaded: {len(df):,}")

# Separate benign and attack samples
benign = df[df['label'] == 0].copy()
attack = df[df['label'] == 1].copy()

print(f"\nClass distribution:")
print(f"  - Benign: {len(benign):,} ({len(benign)/len(df)*100:.1f}%)")
print(f"  - Attack: {len(attack):,} ({len(attack)/len(df)*100:.1f}%)")

# Key DNS features to analyze
dns_features = [
    'protocol',
    'dns_amplification_factor',
    'query_response_ratio',
    'dns_any_query_ratio',
    'dns_txt_query_ratio',
    'dns_server_fanout',
    'dns_response_inconsistency',
    'ttl_violation_rate',
    'dns_queries_per_second',
    'dns_mean_answers_per_query',
    'port_53_traffic_ratio',
    'flow_bytes_per_sec',
    'flow_packets_per_sec',
    'dns_total_queries',
    'dns_total_responses',
    'dns_response_bytes'
]

print("\n" + "=" * 80)
print("BENIGN TRAFFIC CHARACTERISTICS")
print("=" * 80)

# Statistical summary for benign traffic
print("\nDetailed statistics for BENIGN traffic:")
print("-" * 80)

benign_stats = benign[dns_features].describe()
print(benign_stats.T[['count', 'mean', 'std', 'min', '25%', '50%', '75%', 'max']])

# Check for zero values
print("\n" + "=" * 80)
print("ZERO VALUE ANALYSIS (BENIGN)")
print("=" * 80)

for feature in dns_features:
    zero_count = (benign[feature] == 0).sum()
    zero_pct = (zero_count / len(benign)) * 100
    print(f"{feature:35s}: {zero_pct:6.2f}% zeros ({zero_count:,}/{len(benign):,})")

# Protocol distribution
print("\n" + "=" * 80)
print("PROTOCOL DISTRIBUTION (BENIGN)")
print("=" * 80)

protocol_dist = benign['protocol'].value_counts().head(10)
print("\nTop 10 protocol values:")
print(protocol_dist)
print(f"\nUnique protocol values: {benign['protocol'].nunique()}")

# Compare benign vs attack for key features
print("\n" + "=" * 80)
print("BENIGN vs ATTACK COMPARISON (Key Differentiators)")
print("=" * 80)

comparison_features = [
    'dns_amplification_factor',
    'query_response_ratio',
    'dns_queries_per_second',
    'dns_total_queries',
    'dns_total_responses',
    'flow_bytes_per_sec',
    'port_53_traffic_ratio'
]

print(f"\n{'Feature':<35s} {'Benign Mean':>15s} {'Attack Mean':>15s} {'Difference':>15s}")
print("-" * 82)

for feat in comparison_features:
    benign_mean = benign[feat].mean()
    attack_mean = attack[feat].mean()
    diff = abs(benign_mean - attack_mean)
    print(f"{feat:<35s} {benign_mean:>15.4f} {attack_mean:>15.4f} {diff:>15.4f}")

# Realistic ranges for benign traffic (25th to 75th percentile)
print("\n" + "=" * 80)
print("RECOMMENDED BENIGN TRAFFIC RANGES (IQR)")
print("=" * 80)
print("\nThese are the realistic ranges for benign traffic (25th-75th percentile):")
print("Use these for generating test data!\n")

print(f"{'Feature':<35s} {'Min (25%)':>15s} {'Median (50%)':>15s} {'Max (75%)':>15s}")
print("-" * 68)

for feat in dns_features:
    if feat == 'protocol':
        # Protocol is categorical, skip quantile calculation
        continue
    q25 = benign[feat].quantile(0.25)
    q50 = benign[feat].quantile(0.50)
    q75 = benign[feat].quantile(0.75)
    print(f"{feat:<35s} {q25:>15.4f} {q50:>15.4f} {q75:>15.4f}")

# Save benign baseline statistics
baseline_stats = {
    'feature_means': benign[dns_features].mean().to_dict(),
    'feature_stds': benign[dns_features].std().to_dict(),
    'feature_q25': benign[dns_features].quantile(0.25).to_dict(),
    'feature_q50': benign[dns_features].quantile(0.50).to_dict(),
    'feature_q75': benign[dns_features].quantile(0.75).to_dict(),
    'feature_min': benign[dns_features].min().to_dict(),
    'feature_max': benign[dns_features].max().to_dict(),
}

with open('benign_baseline_stats.pkl', 'wb') as f:
    pickle.dump(baseline_stats, f)

print("\n" + "=" * 80)
print("BASELINE SAVED")
print("=" * 80)
print("\nBenign baseline statistics saved to: benign_baseline_stats.pkl")
print("Use these statistics to generate realistic benign test data!")

# Generate sample benign records
print("\n" + "=" * 80)
print("SAMPLE BENIGN RECORDS (First 5)")
print("=" * 80)

print("\nShowing subset of features:")
sample_features = ['protocol', 'dns_amplification_factor', 'query_response_ratio', 
                   'dns_queries_per_second', 'dns_total_queries', 'dns_total_responses',
                   'flow_bytes_per_sec']
print(benign[sample_features].head(5).to_string())

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
