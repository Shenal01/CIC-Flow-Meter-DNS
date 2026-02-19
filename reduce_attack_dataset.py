import pandas as pd
import os

# Configuration
INPUT_FILE = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Attacks\CIC_DDOS_2019_Attacks_ Shuffled.csv"
OUTPUT_FILE = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Attacks\CIC_DDOS_2019_Attacks_Reduced_new.csv"

def reduce_dataset():
    print(f"[INFO] Reading dataset: {INPUT_FILE}")
    
    if not os.path.exists(INPUT_FILE):
        print(f"[FAIL] Error: File not found: {INPUT_FILE}")
        print("       (Make sure you ran the shuffle script first!)")
        return

    try:
        # Read the CSV
        df = pd.read_csv(INPUT_FILE)
        total_rows = len(df)
        print(f"   Total Rows Available: {total_rows:,}")
        
        # Prompt user
        print("\n[INPUT] How many rows do you need in the final CSV?")
        print("       (Enter a number, e.g., 300000)")
        user_input = input("   > ")
        
        # specific handling for "300 000" or "300k"
        cleaned_input = user_input.lower().replace(" ", "").replace("k", "000").replace(",", "")
        
        if not cleaned_input.isdigit():
             print("[FAIL] Invalid number format.")
             return
             
        target_count = int(cleaned_input)
        
        if target_count > total_rows:
            print(f"[WARN] Requested {target_count:,} but only have {total_rows:,}.")
            print("       Taking ALL available rows.")
            target_count = total_rows
            
        # Reduce
        print(f"\n[INFO] Slicing top {target_count:,} rows...")
        # Since it's already shuffled, .head() IS a random sample
        df_reduced = df.head(target_count)
        
        # Save
        print(f"[INFO] Saving to: {OUTPUT_FILE}")
        df_reduced.to_csv(OUTPUT_FILE, index=False)
        print(f"[SUCCESS] Done! Saved {len(df_reduced):,} rows.")
        
    except Exception as e:
        print(f"[ERR] Error: {e}")

if __name__ == "__main__":
    reduce_dataset()
