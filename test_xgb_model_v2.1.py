import sys
import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

# =====================================================================
# CONFIGURATION
# =====================================================================
MODEL_PATH = r"C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\xgb_model_v2.2_advanced.pkl"

# These columns will ALWAYS be dropped before prediction
COLS_TO_DROP = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol_number']

# Protocol values the model was trained on
PROTOCOL_CLASSES = ['DOH', 'DOT', 'TRADITIONAL', 'UNKNOWN', 'TCP', 'UDP']


def preprocess(df, log_features=None):
    """
    Preprocessing — matches training pipeline.
    log_features: list of columns to log1p-transform (v2.2 model bundles this).
    """
    # 1. Drop unwanted columns
    df = df.drop(columns=COLS_TO_DROP, errors='ignore')

    # 2. Extract label if present
    LABEL_MAP = {'BENIGN': 0, 'ATTACK': 1}
    y = None
    if 'label' in df.columns:
        y = df['label'].astype(str).str.upper().map(LABEL_MAP)
        unmapped = y.isna()
        if unmapped.any():
            print(f"[WARN] Unknown labels: {df['label'][unmapped].unique()} -> treated as BENIGN")
        y = y.fillna(0).astype(int).values
        df = df.drop(columns=['label'])

    # 3. Fix NaN / Inf
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)

    # 4. Log-transform skewed features (v2.2 only)
    if log_features:
        for col in log_features:
            if col in df.columns:
                df[col] = np.log1p(df[col].clip(lower=0))

    # 5. Encode protocol
    if 'protocol' in df.columns:
        le_proto = LabelEncoder()
        le_proto.fit(PROTOCOL_CLASSES)
        df['protocol'] = df['protocol'].astype(str).apply(
            lambda x: x if x in PROTOCOL_CLASSES else 'UNKNOWN'
        )
        df['protocol'] = le_proto.transform(df['protocol'])

    return df, y


CLASS_NAMES = {0: 'BENIGN', 1: 'ATTACK'}

def print_report(y_true, y_pred, y_prob, _unused):
    # Fixed names: 0=BENIGN, 1=ATTACK (matches training)
    all_labels  = [0, 1]
    all_names   = ['BENIGN', 'ATTACK']

    # Labels present in ground truth only
    true_labels = sorted(set(y_true))
    true_names  = [CLASS_NAMES[l] for l in true_labels]

    print("\n" + "=" * 65)
    print("  MODEL EVALUATION REPORT")
    print("=" * 65)

    report = classification_report(
        y_true, y_pred,
        labels=true_labels,
        target_names=true_names,
        digits=4,
        zero_division=0
    )
    print(report)

    try:
        auc = roc_auc_score(y_true, y_prob)
        print(f"  ROC-AUC  : {auc:.4f}")
    except Exception:
        print("  ROC-AUC  : N/A (only one class in ground truth)")

    # Confusion matrix — always show both classes with fixed labels [BENIGN=0, ATTACK=1]
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print(f"\n  Confusion Matrix (rows=Actual, cols=Predicted):")
    print(f"                   Pred BENIGN    Pred ATTACK")
    row_names = ['BENIGN', 'ATTACK']
    for i, row in enumerate(cm):
        # Only print rows that have any ground truth samples
        if row.sum() > 0 or True:
            print(f"  Actual {row_names[i]:<10}: {row[0]:<15} {row[1]}")
    print("=" * 65)


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_xgb_model_v2.1.py <path_to_csv>")
        sys.exit(1)

    csv_path = sys.argv[1]

    print(f"[INFO] Loading CSV  : {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"[INFO] Rows Loaded  : {len(df):,}")


    print(f"[INFO] Loading Model: {MODEL_PATH}")
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)

    # v2.2 saves a dict bundle; v2.1 saves the model directly
    if isinstance(bundle, dict):
        model        = bundle['model']
        threshold    = bundle.get('threshold', 0.5)
        log_features = bundle.get('log_features', [])
        print(f"[INFO] Model Version : v2.2 (bundled)")
        print(f"[INFO] Threshold     : {threshold:.2f} (auto-tuned)")
        print(f"[INFO] Log-features  : {len(log_features)} features will be log-transformed")
    else:
        model        = bundle
        threshold    = 0.5
        log_features = []
        print(f"[INFO] Model Version : v2.1 (plain)")
        print(f"[INFO] Threshold     : {threshold:.2f} (default)")

    print("[INFO] Preprocessing (drop cols, encode, log-transform, fix NaN)...")
    X, y = preprocess(df, log_features=log_features)
    print(f"[INFO] Feature Cols  : {X.shape[1]}")

    print("[INFO] Running Predictions...")
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = (y_prob >= threshold).astype(int)

    if y is not None:
        print_report(y, y_pred, y_prob, None)
    else:
        # No label column — just print prediction summary
        attack_count = int(y_pred.sum())
        benign_count = len(y_pred) - attack_count
        print("\n" + "=" * 65)
        print("  PREDICTION SUMMARY (no label column found)")
        print("=" * 65)
        print(f"  Total Flows  : {len(y_pred):,}")
        print(f"  ATTACK       : {attack_count:,}  ({100*attack_count/len(y_pred):.1f}%)")
        print(f"  BENIGN       : {benign_count:,}  ({100*benign_count/len(y_pred):.1f}%)")
        print("=" * 65)

    # ── FINAL VERDICT ─────────────────────────────────────────
    total      = len(y_pred)
    n_attack   = int(y_pred.sum())
    n_benign   = total - n_attack
    pct_attack = 100 * n_attack / total

    print("\n" + "#" * 65)
    if pct_attack >= 20:
        verdict = "*** ATTACK DETECTED ***"
        detail  = f"{n_attack:,} of {total:,} flows flagged as ATTACK ({pct_attack:.1f}%)"
    else:
        verdict = "--- CLEAN TRAFFIC ---"
        detail  = f"Only {n_attack:,} suspicious flows out of {total:,} ({pct_attack:.1f}%)"

    print(f"  FINAL VERDICT : {verdict}")
    print(f"  {detail}")
    print("#" * 65 + "\n")


if __name__ == "__main__":
    main()
