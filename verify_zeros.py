import pandas as pd

# Load the CSV
df = pd.read_csv(r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\DNS_Spoofing.csv')

# Get the 3 samples (Top, Mid, Bot)
rows = df.iloc[[0, len(df)//2, len(df)-1]].copy()

print("=== DEEP DIAGNOSIS OF ZERO COLUMNS AND PROTOCOLS ===\n")

for index, row in rows.iterrows():
    print(f"--- Flow #{index} ---")
    print(f"Tuple: {row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']}")
    print(f"Protocol Label: {row['protocol']}")
    
    # 1. Diagnose Protocol "UNKNOWN"
    if row['protocol'] == "UNKNOWN":
        print("\n[Diagnosis: Why UNKNOWN?]")
        is_53 = (row['src_port'] == 53 or row['dst_port'] == 53)
        is_853 = (row['src_port'] == 853 or row['dst_port'] == 853)
        is_known_doh = (row['is_known_doh_server'] == 1)
        
        if not is_53 and not is_853 and not is_known_doh:
            print("  [PASS] CORRECT. Ports are not 53/853, and Server is not in Trusted DoH List.")
            print("  -> Logic: If it's not Standard DNS, not DoT, and not *Verified* DoH, it defaults to UNKNOWN (Generic Traffic).")
        else:
            print("  [FAIL] ERROR. Should have been detected.")

    # 2. Diagnose "query_response_ratio" (Traditional DNS)
    print(f"\n[Diagnosis: query_response_ratio = {row['query_response_ratio']}]")
    if row['src_port'] != 53 and row['dst_port'] != 53:
        print("  [PASS] CORRECT. This is NOT Port 53.")
        print("  -> Logic: Traditional DNS features are ONLY calculated for Port 53. For others, they are masked to 0.")
    else:
        print("  [CHECK] This IS Port 53. If 0, maybe no Query/Response pairs were seen.")

    # 3. Diagnose "is_known_doh_server"
    print(f"\n[Diagnosis: is_known_doh_server = {row['is_known_doh_server']}]")
    if row['is_known_doh_server'] == 0:
        print(f"  -> Reason: Destination IP {row['dst_ip']} is NOT in the internal DoH Whitelist.")
        if row['dst_port'] == 443:
            print("  -> Context: It is HTTPS (Port 443), but not all HTTPS is DNS. This avoids False Positives.")
    
    # 4. Check other DNS columns
    cols = ['dns_any_query_ratio', 'dns_txt_query_ratio', 'dns_response_inconsistency']
    print(f"\n[Diagnosis: Other DNS Columns]")
    all_zero = all(row[c] == 0 for c in cols)
    if all_zero and (row['src_port'] != 53 and row['dst_port'] != 53):
        print(f"  [PASS] CORRECT. Values are {tuple(row[c] for c in cols)}.")
        print("  -> Reason: Non-Port-53 traffic cannot have DNS flags like ANY or TXT.")
    
    print("\n" + "="*60 + "\n")
