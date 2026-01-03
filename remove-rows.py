import pandas as pd

targets = {
    'DDoS_SynonymousIP_Flood_fixed.csv': 19012,
    'DDoS_SYN_Flood_fixed.csv': 191963,
    'DDoS_TCP_Flood_fixed.csv': 138520
}

base_dir = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\New-CIC-JAVA'

for filename, keep_rows in targets.items():
    input_path = f'{base_dir}\\{filename}'
    output_path = input_path.replace('_fixed.csv', '_balanced.csv')
    
    print(f'Processing {filename}...')
    
    # Read CSV
    df = pd.read_csv(input_path)
    original = len(df)
    
    # Random sample
    sampled = df.sample(n=keep_rows, random_state=42)
    
    # Save
    sampled.to_csv(output_path, index=False)
    
    print(f'  Original: {original:,} rows')
    print(f'  Removed: {original - keep_rows:,} rows')
    print(f'  Kept: {keep_rows:,} rows')
    print(f'  Saved to: {output_path}\n')

print('Done! Balanced files created.')