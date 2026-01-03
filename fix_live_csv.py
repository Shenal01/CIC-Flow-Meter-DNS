"""
DIAGNOSIS: Live CSV Column Misalignment Issue

The problem has been identified:
1. Your live.csv has SHIFTED columns - all data is offset by 1 position
2. The CSV appears to be using the first data row as the header
3. This causes protocol column to contain DNS amplification values
4. Model receives garbage → predicts everything as attack

QUICK FIX: Manually verify and fix the live.csv header structure
"""

import pandas as pd
import numpy as np

# Correct column order (from training data)
CORRECT_COLUMNS = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'dns_amplification_factor', 'query_response_ratio',
    'dns_any_query_ratio', 'dns_txt_query_ratio',
    'dns_server_fanout', 'dns_response_inconsistency',
    'ttl_violation_rate', 'dns_queries_per_second',
    'dns_mean_answers_per_query', 'port_53_traffic_ratio',
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'fwd_packets_per_sec', 'bwd_packets_per_sec',
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'total_fwd_bytes', 'total_bwd_bytes',
    'dns_total_queries', 'dns_total_responses', 'dns_response_bytes',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max',
    'fwd_iat_mean', 'bwd_iat_mean',
    'fwd_packet_length_mean', 'bwd_packet_length_mean',
    'packet_size_std', 'flow_length_min', 'flow_length_max',
    'response_time_variance', 'average_packet_size'
]

print("=" * 80)
print("DIAGNOSING LIVE CSV ISSUE")
print("=" * 80)

# Read the problematic CSV
live_csv = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\live.csv'
print(f"\nReading: {live_csv}")

# Try reading with default settings
df_wrong = pd.read_csv(live_csv)
print(f"\nCurrent structure:")
print(f"  Columns: {list(df_wrong.columns)}")
print(f"  Shape: {df_wrong.shape}")
print(f"\nFirst row protocol value: {df_wrong['protocol'].iloc[0]}")
print(f"  (Should be 'TCP' or 'UDP', but got: {type(df_wrong['protocol'].iloc[0])})")

# Check if first row looks like header
first_row = df_wrong.iloc[0]
print(f"\nFirst data row inspection:")
print(f"  src_ip: {first_row['src_ip']}")
print(f"  dst_ip: {first_row['dst_ip']}")
print(f"  protocol: {first_row['protocol']}")

# Attempt auto-fix
print("\n" + "=" * 80)
print("ATTEMPTING AUTO-FIX")
print("=" * 80)

try:
    # Read raw without header interpretation
    df_raw = pd.read_csv(live_csv, header=None)
    print(f"\nRaw CSV shape: {df_raw.shape}")
    print(f"First row: {df_raw.iloc[0].tolist()[:10]}")
    
    # Check if row 0 looks like a header
    if df_raw.iloc[0, 4] in ['UDP', 'TCP', 'protocol']:
        print("\n✓ Row 0 appears to be a valid header")
        df_fixed = pd.DataFrame(df_raw.values[1:], columns=df_raw.iloc[0])
    else:
        print("\n⚠ Row 0 does not appear to be a header")
        print("  Assigning correct column names manually...")
        
        if df_raw.shape[1] == 40:
            df_fixed = pd.DataFrame(df_raw.values, columns=CORRECT_COLUMNS)
        elif df_raw.shape[1] == 41:
            # Has an extra column (maybe index)
            df_fixed = pd.DataFrame(df_raw.values[:, 1:], columns=CORRECT_COLUMNS)
        else:
            print(f"  ERROR: Unexpected column count: {df_raw.shape[1]}")
            df_fixed = None
    
    if df_fixed is not None:
        # Verify fix
        print(f"\n✓ Fixed CSV shape: {df_fixed.shape}")
        print(f"Protocol column sample: {df_fixed['protocol'].head(10).tolist()}")
        
        # Save fixed version
        output_file = r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\live_FIXED.csv'
        df_fixed.to_csv(output_file, index=False)
        print(f"\n✓ Fixed CSV saved to: {output_file}")
        print(f"\nNow run test_saved_model.py with:")
        print(f"  TEST_DATA_PATH = r'{output_file}'")
        
except Exception as e:
    print(f"\n✗ Auto-fix failed: {e}")
    print("\nMANUAL FIX REQUIRED:")
    print("  1. Open live.csv in a text editor")
    print("  2. Check if the first line is the header")
    print("  3. Ensure protocol column contains 'UDP' or 'TCP', not numbers")
    print("  4. Re-run the Java tool with correct CSV export settings")

print("\n" + "=" * 80)
