import pandas as pd
import os

# Configuration
INPUT_FILE = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Balanced_Attack_and_Benign\Final_balanced_Attack_and_Benign_new.csv"
OUTPUT_FILE = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\Final_Balanced_Attack_and_Benign\Final_balanced_Attack_and_Benign_new_Shuffled.csv"

def shuffle_dataset():
    print(f"[INFO] Reading dataset: {INPUT_FILE}")
    
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: File not found: {INPUT_FILE}")
        return

    try:
        # Read the CSV
        df = pd.read_csv(INPUT_FILE)
        print(f"   Rows loaded: {len(df)}")
        
        # Shuffle the data
        print("[INFO] Shuffling rows (Random State=42 for reproducibility)...")
        df_shuffled = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save
        print(f"[INFO] Saving to: {OUTPUT_FILE}")
        df_shuffled.to_csv(OUTPUT_FILE, index=False)
        print("[SUCCESS] Done! Dataset is fully randomized.")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    shuffle_dataset()
