"""
diagnose_false_positives.py — Shows WHY benign traffic is flagged as ATTACK

Usage:
    python diagnose_false_positives.py <benign_csv_path>

Output:
    - Top features driving ATTACK predictions
    - Statistical comparison vs expected benign ranges
    - Actionable diagnosis
"""
import sys
import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder

MODEL_PATH  = r"C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\xgb_model_new_v2.1.pkl"
COLS_TO_DROP = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol_number']
PROTOCOL_CLASSES = ['DOH', 'DOT', 'TRADITIONAL', 'UNKNOWN', 'TCP', 'UDP']

# Expected ranges for BENIGN traffic (from original training data analysis)
BENIGN_EXPECTED = {
    "flow_packets_per_sec":  (0, 500),
    "flow_bytes_per_sec":    (0, 50000),
    "flow_iat_std":          (50, 100000),    # High variance = human
    "flow_iat_mean":         (10, 500000),
    "packet_size_std":       (10, 300),
    "large_packet_ratio":    (0.0, 0.7),
    "small_packet_ratio":    (0.0, 1.0),
    "sni_entropy":           (0.0, 5.0),
    "dns_queries_per_second":(0, 5),
}


def preprocess(df):
    df = df.drop(columns=COLS_TO_DROP, errors='ignore')
    if 'label' in df.columns:
        df = df.drop(columns=['label'])
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)
    if 'protocol' in df.columns:
        le = LabelEncoder()
        le.fit(PROTOCOL_CLASSES)
        df['protocol'] = df['protocol'].astype(str).apply(
            lambda x: x if x in PROTOCOL_CLASSES else 'UNKNOWN')
        df['protocol'] = le.transform(df['protocol'])
    return df


def main():
    if len(sys.argv) < 2:
        print("Usage: python diagnose_false_positives.py <csv_path>")
        sys.exit(1)

    print(f"[INFO] Loading: {sys.argv[1]}")
    raw = pd.read_csv(sys.argv[1])
    X   = preprocess(raw.copy())

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)[:, 1]

    n_attack = int(y_pred.sum())
    n_benign = len(y_pred) - n_attack
    print(f"\n[RESULT] ATTACK={n_attack}  BENIGN={n_benign}  Total={len(y_pred)}")

    # ── 1. Feature Importance from model ──────────────────────────────
    importance = model.feature_importances_
    feat_names = X.columns.tolist()
    top_feats  = sorted(zip(feat_names, importance), key=lambda x: -x[1])[:15]

    print("\n" + "=" * 65)
    print("  TOP 15 FEATURES (Model uses these most for decisions)")
    print("=" * 65)
    for f, imp in top_feats:
        bar = "#" * int(imp * 200)
        print(f"  {f:<35} {imp:.4f}  {bar}")

    # ── 2. Check each feature against expected benign ranges ──────────
    print("\n" + "=" * 65)
    print("  FEATURE DIAGNOSTIC (Comparing test data vs expected benign)")
    print("=" * 65)
    print(f"  {'Feature':<35} {'TestMean':>10} {'TestMax':>12} {'ExpectedRange':>20}  Status")
    print("  " + "-" * 95)

    issues = []
    for feat, (lo, hi) in BENIGN_EXPECTED.items():
        if feat not in X.columns:
            continue
        col          = X[feat]
        test_mean    = col.mean()
        test_max     = col.max()
        pct_outside  = (col > hi).mean() * 100
        status       = "OK" if pct_outside < 5 else f"!! {pct_outside:.0f}% rows ABOVE LIMIT"
        if pct_outside >= 5:
            issues.append((feat, test_mean, test_max, hi, pct_outside))
        print(f"  {feat:<35} {test_mean:>10.2f} {test_max:>12.2f} {f'[{lo}, {hi}]':>20}  {status}")

    # ── 3. Root cause summary ─────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  ROOT CAUSE DIAGNOSIS")
    print("=" * 65)
    if not issues:
        print("  All features within expected benign ranges.")
        print("  The problem may be in feature COMBINATIONS, not individual values.")
    else:
        print(f"  Found {len(issues)} features with values outside benign ranges:\n")
        for feat, mean, mx, limit, pct in sorted(issues, key=lambda x: -x[4]):
            print(f"  [!!] {feat}")
            print(f"       Test mean={mean:.2f}, Test max={mx:.2f}, Benign limit={limit}")
            print(f"       {pct:.0f}% of flows exceed the benign threshold")
            print()
        print("  CONCLUSION: These features are why the model flags benign as attack.")
        print("  The test CSV traffic has HIGHER values in these features than real benign.")
        print("  Fix: Capture REAL traffic (not generated) to get accurate benign features.")

    # ── 4. Protocol distribution ──────────────────────────────────────
    if 'protocol' in raw.columns:
        print("\n" + "=" * 65)
        print("  PROTOCOL DISTRIBUTION IN TEST CSV")
        print("=" * 65)
        proto_counts = raw['protocol'].value_counts()
        for proto, cnt in proto_counts.items():
            print(f"  {proto:<15}: {cnt:>6} rows  ({100*cnt/len(raw):.1f}%)")

if __name__ == "__main__":
    main()
