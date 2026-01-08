import pandas as pd

# Load the most recent DNS capture
df = pd.read_csv('dns_detection_enhanced_20260104_184828.csv')

columns_to_check = [
    'dns_any_query_ratio',
    'dns_txt_query_ratio', 
    'dns_server_fanout',
    'ttl_violation_rate',
    'dns_total_queries',
    'dns_total_responses'
]

print("=" * 70)
print("ANALYZING EXISTING DNS CAPTURE DATA")
print("File: dns_detection_enhanced_20260104_184828.csv")
print("=" * 70)

print(f"\nTotal rows: {len(df)}")

print("\n" + "=" * 70)
print("COLUMN STATISTICS")
print("=" * 70)
print(df[columns_to_check].describe())

print("\n" + "=" * 70)
print("NON-ZERO VALUE COUNTS")
print("=" * 70)
for col in columns_to_check:
    non_zero = (df[col] != 0).sum()
    print(f"{col:30s}: {non_zero:5d} non-zero / {len(df):5d} total ({100*non_zero/len(df):.1f}%)")

print("\n" + "=" * 70)
print("SAMPLE DATA (First 10 Rows)")
print("=" * 70)
print(df[columns_to_check].head(10).to_string())

print("\n" + "=" * 70)
print("VERDICT")
print("=" * 70)

any_ratio_nonzero = (df['dns_any_query_ratio'] != 0).sum()
txt_ratio_nonzero = (df['dns_txt_query_ratio'] != 0).sum()

if any_ratio_nonzero > 0 or txt_ratio_nonzero > 0:
    print("[SUCCESS] DNS query type ratios ARE being extracted!")
    print(f"          Found {any_ratio_nonzero} flows with ANY queries")
    print(f"          Found {txt_ratio_nonzero} flows with TXT queries")
else:
    print("[FAILED] DNS query type ratios are ALL ZERO")
    print("         This confirms the feature extraction issue.")
    
dns_flows = (df['dns_total_queries'] > 0).sum()
print(f"\n[INFO] Total DNS flows detected: {dns_flows}/{len(df)}")

print("=" * 70)
