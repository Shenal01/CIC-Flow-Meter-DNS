import pandas as pd
import sys
import os

# Set stdout to UTF-8
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

def verify_csv_structure(csv_path):
    print(f"Verifying CSV: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return False

    # 1. Check Protocol Column (Should be first)
    if 'protocol' not in df.columns:
        print("Protocol column missing!")
        return False
    
    if df.columns[0] != 'protocol':
        print(f"Protocol is not the first column. Found: {df.columns[0]}")
        return False
        
    print("Protocol column verified (Position 1)")

    # 2. Check Removed Columns
    removed_cols = ['dns_mean_answers_per_query', 'dns_server_fanout', 'ttl_violation_rate']
    for col in removed_cols:
        if col in df.columns:
            print(f"Deprecated column found: {col} (Should be removed)")
            return False
    print("Deprecated columns correctly removed")

    # 3. Check New Encrypted Features
    new_cols = [
        'large_packet_ratio', 
        'medium_packet_ratio', 
        'small_packet_ratio', 
        'sni_entropy', 
        'is_known_doh_server', 
        'encrypted_payload_size_variance'
    ]
    
    missing_new = [col for col in new_cols if col not in df.columns]
    if missing_new:
        print(f"Missing new features: {missing_new}")
        return False
        
    print("All 6 new encrypted features present")
    
    # 4. Data Validity Check
    # Check if packet ratios sum to approx 1.0 (allow small float error)
    if len(df) > 0:
        ratios = df['large_packet_ratio'] + df['medium_packet_ratio'] + df['small_packet_ratio']
        # Check if any row sums to > 1.01 or < 0.99 (ignoring 0/0 case which is handled)
        invalid_ratios = ratios[(ratios > 1.01) | (ratios < 0.99)]
        # Filter out rows where sum is 0 (empty flows)
        invalid_ratios = invalid_ratios[ratios != 0]
        
        if not invalid_ratios.empty:
             print(f"Warning: {len(invalid_ratios)} rows have invalid packet size ratios")
             print(invalid_ratios.head())
        else:
             print("Packet size ratios sum to 1.0")

    print(f"\nValidation Successful! Total Columns: {len(df.columns)}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_v2_csv.py <csv_file>")
        sys.exit(1)
        
    verify_csv_structure(sys.argv[1])
