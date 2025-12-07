# Feature Engineering & Pre-processing Guide

This document outlines the critical steps to prepare your Antigravity CSV data for training a Machine Learning model (Random Forest, SVM, Neural Network).

## 1. Data Cleaning (The "Must Dos")
Before you do anything, you must remove features that will cause your model to "cheat" or overfit.

*   **DROP these columns**:
    *   `Src IP`, `Dst IP`
    *   `Src Port`, `Dst Port`
    *   `Flow ID` (if present)
    *   `Timestamp`
*   **Reason**: You want your model to learn *behavior* ("High entropy is bad"), not *location* ("IP 192.168.1.5 is bad"). IP addresses change every day; behavior does not.

## 2. Handling Categorical Data (Encoding)
Machine Learning models only understand numbers, not strings.

*   **`Protocol`**: It is likely always "UDP" (17) or "TCP" (6).
    *   *Action*: Keep as is (Integer) OR One-Hot Encode if you see strings like "UDP".
*   **`dns_opcode`**: This is a number (0, 1, 5).
    *   *Action*: Treat as **Categorical**. Use **One-Hot Encoding**.
    *   *Why?*: OpCode 5 (Update) is not "5 times bigger" than OpCode 1 (Query). They are different *types* of actions.
*   **`dns_rcode`**: This is a number (0, 3, 2).
    *   *Action*: One-Hot Encode.
    *   *Why?* RCode 3 (NXDOMAIN) is a specific error signal, not a magnitude.

## 3. Scaling (Normalization)
Your features have vastly different ranges.
*   `queries_per_second` might range from 0 to 10,000.
*   `nxdomain_rate` ranges from 0.0 to 1.0.

If you don't scale, the model will think `queries_per_second` is 10,000x more important than `nxdomain_rate`.

*   **Algorithm**: Use **Min-Max Scaling** (0 to 1) or **Standard Scaler** (Z-score).
*   **Target Features**:
    *   `Flow Duration`
    *   `Flow Bytes/s`
    *   `dns_query_length`
    *   `dns_response_size`
    *   `dns_answer_ttls_mean`

## 4. Derived ratios (Advanced Tips)
You can create *new* features from the existing ones to help the model distinct attacks.

*   **Byte Ratio**: `dns_response_size / dns_query_size`
    *   *Detects*: **Amplification**. If this ratio is > 50, it's immediately suspicious.
*   **Error Ratio**: `dns_rcode == 3 (NXDOMAIN) / Total Responses`
    *   *Detects*: **DGA / Water Torture**. You already have `nxdomain_rate` which does this!

## 5. Handling Imbalance
Cybesecurity data is always imbalanced (99% Benign, 1% Attack).

*   **Technique**: SMOTE (Synthetic Minority Over-sampling Technique).
*   **Goal**: Generate fake "Attack" samples to balance the dataset 50/50.
*   **Warning**: Only Apply SMOTE to your **Training Set**, NEVER your **Test Set**.

## Summary Checklist
1.  [ ] **Drop** IPs/Ports/Time.
2.  [ ] **One-Hot Encode** `opcode` and `rcode`.
3.  [ ] **Scale** all continuous values (Duration, Length, Counts) to [0,1].
4.  [ ] **Check for NaNs**: Replace `Infinity` or `NaN` (caused by divide-by-zero) with -1 or 0.
