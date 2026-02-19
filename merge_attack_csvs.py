import pandas as pd
import glob
import os

# Configuration
INPUT_DIR = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Attacks\balanced_Attacks_Final"
OUTPUT_FILE = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Attacks\balanced_Attacks_Final\Final_balanced_Attacks_new.csv"

def merge_csvs():
    print(f"🔍 Scanning directory: {INPUT_DIR}")
    
    # Get all CSV files
    all_files = glob.glob(os.path.join(INPUT_DIR, "*.csv"))
    
    if not all_files:
        print("❌ No CSV files found!")
        return

    print(f"Found {len(all_files)} files:")
    for f in all_files:
        print(f" - {os.path.basename(f)}")

    df_list = []
    
    for filename in all_files:
        try:
            print(f"\n📖 Reading: {os.path.basename(filename)}")
            df = pd.read_csv(filename, index_col=None, header=0)
            
            # Optional: Verify if it's empty
            if df.empty:
                print(f"⚠️ Warning: {os.path.basename(filename)} is empty. Skipping.")
                continue
                
            print(f"   Rows: {len(df)}")
            df_list.append(df)
            
        except Exception as e:
            print(f"❌ Error reading {filename}: {e}")

    if not df_list:
        print("❌ No data to merge.")
        return

    print("\n🔄 Merging datasets...")
    # Concatenate all dataframes
    final_df = pd.concat(df_list, axis=0, ignore_index=True)
    
    print(f"✅ Merge Complete! Total Rows: {len(final_df)}")
    
    # Save
    print(f"💾 Saving to: {OUTPUT_FILE}")
    final_df.to_csv(OUTPUT_FILE, index=False)
    print("🎉 Done!")

if __name__ == "__main__":
    merge_csvs()
