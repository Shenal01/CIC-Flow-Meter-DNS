import pandas as pd

# Load data
df = pd.read_csv('dns_detection_enhanced_20260104_184828.csv')

print("=" * 70)
print("DNS SERVER FANOUT ANALYSIS")
print("=" * 70)

# Check if column exists and what values it has
print(f"\n1. Column statistics:")
print(df['dns_server_fanout'].describe())

print(f"\n2. Unique values: {df['dns_server_fanout'].unique()}")
print(f"\n3. Value counts:")
print(df['dns_server_fanout'].value_counts())

# Check if it has ANY variation
std_dev = df['dns_server_fanout'].std()
print(f"\n4. Standard deviation: {std_dev}")

if std_dev == 0:
    print("\n" + "=" * 70)
    print("VERDICT: Feature is USELESS for ML")
    print("=" * 70)
    print("- All values are identical (0)")
    print("- Zero variance = zero predictive power")
    print("- Model cannot learn from this feature")
    print("- Safe to IGNORE or REMOVE from model")
else:
    print("\n" + "=" * 70)
    print("VERDICT: Feature has variation")
    print("=" * 70)
