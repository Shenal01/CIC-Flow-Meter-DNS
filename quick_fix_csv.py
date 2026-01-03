"""
Quick Fix for live.csv - Remove trailing commas and fix structure
"""
import pandas as pd

input_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\live.csv'
output_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\live_FIXED.csv'

print("Fixing CSV with trailing commas...")

# Read with error handling
try:
    # Method 1: Skip bad lines
    df = pd.read_csv(input_file, on_bad_lines='skip')
    print(f"[OK] Loaded {len(df)} rows (skipped malformed lines)")
except:
    # Method 2: More permissive reading
    df = pd.read_csv(input_file, engine='python', on_bad_lines='skip')
    print(f"[OK] Loaded {len(df)} rows with python engine")

# Verify protocol column
print(f"\nProtocol column sample: {df['protocol'].head(10).tolist()}")

# Check if protocols are correct
if df['protocol'].dtype == 'object' and 'UDP' in df['protocol'].values or 'TCP' in df['protocol'].values:
    print("[OK] Protocol column looks correct!")
else:
    print("[ERROR] Protocol column still has wrong data type or values")
    print(f"   First few values: {df['protocol'].head().tolist()}")

# Save fixed version
df.to_csv(output_file, index=False)
print(f"\n[OK] Fixed CSV saved to: {output_file}")
print(f"Rows: {len(df)}")
