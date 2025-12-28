# Feature Engineering Walkthrough (Real Data Example)

This document demonstrates exactly how to transform raw CSV data into an ML-ready matrix, using 3 real rows sampled from your dataset.

---

## 1. The Raw Data (Input)
*Selected 3 random rows from `dns_spoofing_new.csv`.*

| Row | Src IP | Dst IP | Protocol | Duration | Flow Len Mean | DNS QR | DNS QPS | Amp Factor |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A** | `192.168.137.220` | `255.255.255.255` | `UDP` | `297157` | `214.0` | `0` (Null) | `0.0` | `0.0` |
| **B** | `192.168.137.91` | `255.255.255.255` | `UDP` | `0` | `82.0` | `0` (Query) | `0.0` | `0.0` |
| **C** | `192.168.137.49` | `205.174.165.69` | `UDP` | `11991` | `94.0` | `0` (Null) | `0.0` | `0.0` |

---

## 2. Step-by-Step Transformation

### Step 1: DROP Identity (Cleaning)
**Action**: Delete `Src IP`, `Dst IP`, `Src Port`, `Dst Port`.
**Reason**: We want to learn *behavior*, not *IP addresses*.

### Step 2: ENCODE Categories (Text -> Numbers)
**Action**: Convert `Protocol` ("UDP") to `1`.
**Action**: If `DNS QR` was "Query", it's already `0`. If "Response", it would be `1`.

| Row | Protocol (Encoded) | Duration | Flow Len Mean | DNS QR |
| :--- | :--- | :--- | :--- | :--- |
| **A** | **1** | 297157 | 214.0 | 0 |
| **B** | **1** | 0 | 82.0 | 0 |
| **C** | **1** | 11991 | 94.0 | 0 |

### Step 3: SCALE (Normalization)
**Action**: Apply `MinMaxScaler` to squeeze values between `0.0` and `1.0`.
*   **Formula**: `(Value - Min) / (Max - Min)`
*   *Assumption for Example*: Max Duration = `300,000`, Max Len = `1500`.

**Calculation (Example)**:
*   **Row A Duration**: `297157 / 300000` = **0.99**
*   **Row B Duration**: `0 / 300000` = **0.00**
*   **Row A Len**: `214 / 1500` = **0.14**

| Row | Protocol | Duration (Scaled) | Flow Len (Scaled) | DNS QR |
| :--- | :--- | :--- | :--- | :--- |
| **A** | 1 | **0.99** | **0.14** | 0 |
| **B** | 1 | **0.00** | **0.05** | 0 |
| **C** | 1 | **0.04** | **0.06** | 0 |

> **Result**: All numbers are now "Machine Readable" and comparable.

---

## 3. Final ML Input List (The "Green List")
These are the **Exact Columns** you must provide to your model (Random Forest/SVM) after processing.

### A. Core Metrics (Scaled 0.0 - 1.0)
1.  `Flow Duration`
2.  `Tot Fwd Pkts`
3.  `Tot Bwd Pkts`
4.  `Flow Len Mean`
5.  `Flow Len Std`
6.  `Flow Len Max`
7.  `Flow IAT Mean`
8.  `Flow IAT Std`
9.  `Flow IAT Max`
10. `queries_per_second`
11. `dns_amplification_factor`
12. `query_response_ratio`
13. `packet_size_stddev`
14. `dns_any_query_ratio`
15. `dns_txt_query_ratio`

### B. Flags & Counters (Binary/Encoded)
16. `Protocol` (Mapped to 0/1)
17. `dns_qr` (0 or 1)
18. `dns_opcode` (One-Hot Encoded: `opcode_0`, `opcode_5`...)
19. `dns_query_type` (One-Hot Encoded: `type_1`, `type_255`...)
20. `dns_edns_present` (0 or 1)
