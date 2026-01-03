"""
RUN ALL STEPS - Complete pipeline to create final dataset
"""
import subprocess
import sys

scripts = [
    'step1_merge_attacks.py',
    'step2_merge_benign.py',
    'step3_combine_final.py'
]

print("\n" + "=" * 60)
print("RUNNING COMPLETE DATASET PREPARATION PIPELINE")
print("=" * 60 + "\n")

for i, script in enumerate(scripts, 1):
    print(f"\nRunning {script}...")
    print("-" * 60)
    
    result = subprocess.run([sys.executable, script], capture_output=False)
    
    if result.returncode != 0:
        print(f"\n✗ ERROR: {script} failed!")
        sys.exit(1)
    
    print(f"✓ {script} completed successfully\n")

print("\n" + "=" * 60)
print("ALL STEPS COMPLETED SUCCESSFULLY!")
print("=" * 60)
print("\nYour final dataset is ready at:")
print("C:\\Users\\shenal\\Downloads\\reseraach\\CIC_IOT_2023\\PCAP\\FinalDataset\\final_balanced_dataset.csv")
print("\nNext step: Train your XGBoost model! 🚀")
print("=" * 60 + "\n")
