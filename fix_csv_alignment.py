"""
Fix CSV Column Misalignment from CIC-Flow-Meter-DNS Tool

The CIC-Flow-Meter tool outputs CSV correctly, but when pandas reads it with default settings,
it sometimes interprets the first data column as an index. This script fixes the misalignment.
"""

import pandas as pd
import sys

def fix_csv_alignment(input_file, output_file=None):
    """
    Fix CSV file that has been read with first column as index
    by properly reading it and resaving
    """
    print("=" * 80)
    print("FIXING CSV COLUMN ALIGNMENT")
    print("=" * 80)
    
    print(f"\nInput file: {input_file}")
    
    # Read the CSV with the first column treated properly as data (not index)
    print("\nStep 1: Reading CSV with proper column handling...")
    try:
        # First try: Read normally (this is how it SHOULD be read)
        df = pd.read_csv(input_file)
        
        print(f"   Loaded {len(df):,} rows")
        print(f"   Columns: {list(df.columns[:5])}...")
        
        # Check if it's already corrupted (dst_ip is int instead of IP string)
        if df['dst_ip'].dtype == 'int64':
            print("\n   [!] Detected column misalignment!")
            print("   Reloading with first column as index to reverse the shift...")
            
            # Read again with first column as index (to get the hidden src_ip back)
            df = pd.read_csv(input_file, index_col=0)
            
            # The index now contains src_ip values
            df.reset_index(inplace=True)
            df.rename(columns={'index': 'src_ip'}, inplace=True)
            
            print(f"   ✓ Recovered src_ip column from index")
            print(f"   ✓ Now have {len(df.columns)} columns")
        else:
            print("\n   ✓ CSV appears to be correctly formatted already!")
            
    except Exception as e:
        print(f"\n   [ERROR] Failed to read file: {e}")
        return False
    
    # Verify the protocol column
    print("\nStep 2: Verifying data integrity...")
    
    print(f"   Protocol column type: {df['protocol'].dtype}")
    print(f"   Protocol unique values: {df['protocol'].unique()[:5]}")
    
    if df['protocol'].dtype == 'float64':
        print("   [!] WARNING: Protocol column still contains floats!")
        print("   This indicates the file may be too corrupted to fix automatically.")
        print("   Consider regenerating the traffic capture.")
        # Continue anyway to see what we get
    
    # Check expected columns
    expected_first_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    actual_first_cols = list(df.columns[:5])
    
    print(f"\n   Expected first 5 columns: {expected_first_cols}")
    print(f"   Actual first 5 columns:   {actual_first_cols}")
    
    if actual_first_cols == expected_first_cols:
        print("   ✓ Column names match expected format!")
    else:
        print("   [!] Column names don't match - file may be corrupted")
    
    # Save corrected file
    if output_file is None:
        output_file = input_file.replace('.csv', '_FIXED.csv')
    
    print(f"\nStep 3: Saving corrected CSV...")
    print(f"   Output file: {output_file}")
    
    # CRITICAL: Save with index=False to prevent the problem from happening again!
    df.to_csv(output_file, index=False)
    
    print(f"   ✓ Saved {len(df):,} rows with {len(df.columns)} columns")
    
    # Verify the saved file
    print("\nStep 4: Verifying saved file...")
    df_verify = pd.read_csv(output_file)
    
    print(f"   Reloaded file has {len(df_verify):,} rows, {len(df_verify.columns)} columns")
    print(f"   First 5 columns: {list(df_verify.columns[:5])}")
    print(f"   Protocol dtype: {df_verify['protocol'].dtype}")
    print(f"   Sample protocol values: {df_verify['protocol'].unique()[:5]}")
    
    print("\n" + "=" * 80)
    print("FIX COMPLETE")
    print("=" * 80)
    print(f"\n✓ Corrected file saved as: {output_file}")
    print("\nNOTE: If protocol column still contains floats instead of 'UDP'/'TCP',")
    print("      the original CSV was too corrupted. Regenerate the capture.")
    
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fix_csv_alignment.py <input_csv_file> [output_csv_file]")
        print("\nExample:")
        print("  python fix_csv_alignment.py benign_generated_mix.csv")
        print("  python fix_csv_alignment.py benign_generated_mix.csv fixed_benign.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    fix_csv_alignment(input_file, output_file)
