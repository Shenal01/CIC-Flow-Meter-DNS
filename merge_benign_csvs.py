import pandas as pd
import glob
import os

# Configuration
INPUT_DIR = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Balanced_Attack_and_Benign"
OUTPUT_FILE = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Balanced_Attack_and_Benign\Final_balanced_Attack_and_Benign_new.csv"

def merge_csvs():
    print(f"[INFO] Scanning directory: {INPUT_DIR}")
    
    # Get all CSV files
    all_files = glob.glob(os.path.join(INPUT_DIR, "*.csv"))
    
    if not all_files:
        print("[FAIL] No CSV files found!")
        return

    print(f"Found {len(all_files)} files:")
    for f in all_files:
        print(f" - {os.path.basename(f)}")

    df_list = []
    
    for filename in all_files:
        try:
            print(f"\n[INFO] Reading: {os.path.basename(filename)}")
            df = pd.read_csv(filename, index_col=None, header=0)
            
            # Optional: Verify if it's empty
            if df.empty:
                print(f"[WARN] {os.path.basename(filename)} is empty. Skipping.")
                continue
                
            print(f"   Rows: {len(df)}")
            df_list.append(df)
            
        except Exception as e:
            print(f"[ERR] Error reading {filename}: {e}")

    if not df_list:
        print("[FAIL] No data to merge.")
        return

    print("\n[INFO] Merging datasets...")
    # Concatenate all dataframes
    final_df = pd.concat(df_list, axis=0, ignore_index=True)
    
    print(f"[SUCCESS] Merge Complete! Total Rows: {len(final_df)}")
    
    # Save
    print(f"[INFO] Saving to: {OUTPUT_FILE}")
    final_df.to_csv(OUTPUT_FILE, index=False)
    print("[SUCCESS] Done!")

if __name__ == "__main__":
    merge_csvs()
