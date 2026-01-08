import pandas as pd

# Load the problematic CSV file
df = pd.read_csv(r'C:\Users\shenal\Downloads\reseraach\Attacks\Attacks\benign_generated_mix.csv', nrows=5)

print("=" * 80)
print("ANALYZING CSV STRUCTURE")
print("=" * 80)

print("\nColumn names:")
print(list(df.columns))

print("\n" + "=" * 80)
print("FIRST 3 ROWS (ALL COLUMNS)")
print("="  * 80)
print(df.head(3))

print("\n" + "=" * 80)
print("COLUMN DATA TYPES")
print("=" * 80)
print(df.dtypes)

print("\n" + "=" * 80)
print("DETAILED COLUMN INSPECTION (First Row)")
print("=" * 80)

for i, col in enumerate(df.columns):
    val = df[col].iloc[0]
    print(f"{i:2d}. {col:35s} = {val} ({type(val).__name__})")
