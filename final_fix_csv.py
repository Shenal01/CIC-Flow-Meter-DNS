"""
FINAL FIX: The CSV has a trailing comma causing an extra empty column
This script removes it and creates a clean CSV
"""
import pandas as pd

input_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\live.csv'
output_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\live_FIXED.csv'

print("=" * 80)
print("FIXING LIVE CSV - Removing Trailing Commas")
print("=" * 80)

# Read the CSV file manually to remove trailing commas
with open(input_file, 'r') as f:
    lines = f.readlines()

# Remove trailing commas from each line
fixed_lines = []
for line in lines:
    fixed_line = line.rstrip('\r\n,') + '\n'  # Remove trailing commas and whitespace
    fixed_lines.append(fixed_line)

# Write fixed CSV
with open(output_file, 'w', newline='') as f:
    f.writelines(fixed_lines)

print(f"\n[OK] Removed trailing commas from {len(lines)} lines")

# Now read and verify
df = pd.read_csv(output_file)
print(f"\n[OK] Successfully loaded {len(df)} rows × {df.shape[1]} columns")
print(f"\nProtocol column sample: {df['protocol'].head(10).tolist()}")
print(f"Protocol data type: {df['protocol'].dtype}")

# Verify protocols
tcp_count = (df['protocol'] == 'TCP').sum()
udp_count = (df['protocol'] == 'UDP').sum()
print(f"\nProtocol distribution:")
print(f"  TCP: {tcp_count}")
print(f"  UDP: {udp_count}")

if tcp_count + udp_count == len(df):
    print("\n[OK] ✓ ALL PROTOCOLS ARE CORRECT!")
    print(f"\n[OK] Fixed CSV saved to: {output_file}")
    print("\nYou can now test with:")
    print(f"  TEST_DATA_PATH = r'{output_file}'")
else:
    print(f"\n[WARNING] Protocol column may still have issues")
    print(f"  Valid protocols: {tcp_count + udp_count}/{len(df)}")

print("\n" + "=" * 80)
