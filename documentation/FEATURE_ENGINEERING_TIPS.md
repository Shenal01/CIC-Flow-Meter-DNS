# Feature Engineering & Pre-processing Guide

This document outlines the critical steps to prepare your **Antigravity CSV data** for training a Machine Learning model (Random Forest, SVM, Neural Network).

> **Direct Usage? NO.**
> You cannot feed the raw CSV directly into a model. You must perform the following 4 steps.

## 1. Data Cleaning (Drop "Cheating" Features)
Remove columns that let the model memorize specific machines instead of learning behavior.

*   **DROP these columns**:
    *   `Src IP`, `Dst IP`
    *   `Src Port`, `Dst Port`
    *   `Timestamp` (if present)
*   **Reason**: IP addresses change. Behavior (High Amplification) does not.

## 2. Encoding (Text to Numbers)
Models need numbers. Convert categorical strings/IDs.

*   **`Protocol`**: Convert `TCP`/`UDP` -> `0`/`1` (Label Encoding).
*   **`dns_opcode`**: One-Hot Encode (0, 1, 5). Update (5) is a different *action* than Query (0), not "bigger".
*   **`dns_query_type`**: One-Hot Encode (1, 28, 255, 16). `ANY` (255) is a type, not a magnitude.

## 3. Scaling (Normalization)
Features have vastly different ranges. You must scale them to `[0, 1]` (MinMax) or `Mean=0` (StandardScaler).

*   **Why?** `Flow Duration` (120,000 ms) will drown out `dns_amplification_factor` (10.0) if not scaled.
*   **Apply Scaling to**:
    *   `Flow Duration`
    *   `Flow Len Mean`, `Flow Len Std`, `Flow Len Max`
    *   `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`
    *   `queries_per_second`
    *   `dns_amplification_factor`
    *   `packet_size_stddev`

## 4. The "Green List" (Safe to Use)
Once you have Dropped IPs and Encoded Categories, **ALL** of the following are excellent signals for your model:

### A. Volume & Shape (Scale these!)
*   `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`
*   `Flow Len Mean`, `Flow Len Std`, `Flow Len Max`
*   `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`
*   `queries_per_second`

### B. DNS Behavior (The "Smart" Features)
*   `dns_qdcount`, `dns_answer_count`
*   `dns_total_queries`, `dns_total_responses`
*   `dns_amplification_factor` (Critical for Amp attacks)
*   `query_response_ratio` (Critical for Floods)
*   `packet_size_stddev` (Critical for Botnets)

### C. Flags & Indicators (Binary - No Scaling Needed)
*   `dns_qr` (0 or 1)
*   `dns_edns_present` (0 or 1)

## 5. Handling NaNs & Infinity
The tool calculates ratios. If denominator is zero, you get `Infinity` or `NaN`.

*   **Check**: `dns_amplification_factor`, `query_response_ratio`.
*   **Fix**: Replace `Infinity` with `-1` (or Max Value). Replace `NaN` with `0`.

## 5. Summary Checklist (Python/Pandas)
```python
# 1. Drop Identity
df = df.drop(['Src IP', 'Dst IP', 'Src Port', 'Dst Port'], axis=1)

# 2. Encode Protocol
df['Protocol'] = df['Protocol'].map({'TCP': 0, 'UDP': 1})

# 3. Handle Infinity (Divide by Zero)
df.replace([np.inf, -np.inf], -1, inplace=True)
df.fillna(0, inplace=True)

# 4. Scale
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
df[cols_to_scale] = scaler.fit_transform(df[cols_to_scale])
```
