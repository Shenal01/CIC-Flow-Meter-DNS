# Model Testing Guide - XGBoost DNS Abuse Detection

This guide explains how to test your saved XGBoost model on new data.

---

## Quick Start

### Option 1: Using the Test Script (Recommended)

```bash
cd c:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS
python test_saved_model.py
```

The script automatically:
- Loads your saved model
- Preprocesses test data
- Makes predictions
- Evaluates performance (if labels available)
- Saves predictions to CSV

### Option 2: Manual Testing in Python

```python
import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

# 1. Load the model
with open('xgboost_dns_abuse_infrastructure_model.pkl', 'rb') as f:
    model = pickle.load(f)

# 2. Load your test data
df = pd.read_csv('your_test_data.csv')

# 3. Preprocess (same as training)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)
df = df.drop(['src_ip', 'dst_ip', 'src_port', 'dst_port'], axis=1)

# Encode protocol
le = LabelEncoder()
df['protocol'] = le.fit_transform(df['protocol'])

# 4. Separate features
X_test = df.drop('label', axis=1)  # Remove if no labels
y_test = df['label']  # Remove if no labels

# 5. Make predictions
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)

# 6. View results
print("Predictions:", predictions[:10])
print("Probabilities:", probabilities[:10])
```

---

## Configuration Options

Edit the following variables in `test_saved_model.py`:

### Model Settings
```python
MODEL_FILE = 'xgboost_dns_abuse_infrastructure_model.pkl'  # Your model filename
MODEL_FORMAT = 'pkl'  # 'pkl' or 'json'
```

### Data Settings
```python
TEST_DATA_PATH = r'path\to\your\test_data.csv'  # Your test data
NUM_SAMPLES = 1000  # Number of samples to test (None = all)
```

### Output Settings
```python
SAVE_PREDICTIONS = True  # Save predictions to CSV
```

---

## Understanding the Output

### 1. Model Loading
```
✓ Model loaded successfully from Pickle file
Model Info:
  - Type: XGBClassifier
  - Number of features expected: 36
```

### 2. Prediction Distribution
```
Prediction distribution:
  - BENIGN (0): 523 (52.30%)
  - ATTACK (1): 477 (47.70%)
```

### 3. Sample Predictions
```
Index    Actual     Predicted    Prob(BENIGN)    Prob(ATTACK)
0        BENIGN     BENIGN       0.9854          0.0146
1        ATTACK     ATTACK       0.0234          0.9766
```

### 4. Performance Metrics (if labels available)
```
Accuracy: 0.9542 (95.42%)

Confusion Matrix:
[[478  18]
 [ 28 476]]

Classification Report:
              precision    recall  f1-score
BENIGN          0.9447    0.9637    0.9541
ATTACK          0.9636    0.9444    0.9539

ROC-AUC Score: 0.9872
```

---

## Testing Scenarios

### Scenario 1: Test on Held-Out Data from Training Set

**Use Case**: Verify model works correctly on data it hasn't seen.

```python
# In test_saved_model.py, set:
TEST_DATA_PATH = r'C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\FinalDataset\final_balanced_dataset.csv'
NUM_SAMPLES = 5000  # Test on 5000 samples
```

**Expected Result**: High accuracy (>90%) since it's from the same distribution.

---

### Scenario 2: Test on Brand New PCAP Data

**Use Case**: Test on traffic captured after model training.

**Steps**:
1. Process new PCAP with CICFlowMeter to generate CSV
2. Update `TEST_DATA_PATH` to new CSV
3. The CSV may not have labels - that's okay!

```python
# Script will handle unlabeled data
# Predictions will be made, but evaluation skipped
```

---

### Scenario 3: Test Single Flow/Sample

**Create a test file**:
```python
import pandas as pd

# Single DNS flow example
single_flow = {
    'protocol': ['UDP'],
    'dns_amplification_factor': [15.5],
    'query_response_ratio': [0.1],
    'dns_queries_per_second': [1500.0],
    'packet_size_std': [5.2],
    'flow_duration': [120000],
    # ... add all 36 features
}

df = pd.DataFrame(single_flow)
df.to_csv('single_test_flow.csv', index=False)
```

Then test:
```python
TEST_DATA_PATH = 'single_test_flow.csv'
NUM_SAMPLES = None
```

---

## Troubleshooting

### Error: Feature count mismatch

**Problem**:
```
Model expects: 36 features
Data has: 40 features
```

**Solution**: Ensure you drop the same columns as training:
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `label` (when making predictions)

---

### Error: Cannot load pickle file

**Problem**:
```
ModuleNotFoundError: No module named 'xgboost'
```

**Solution**:
```bash
pip install xgboost scikit-learn pandas numpy
```

---

### Warning: Probability scores seem random

**Problem**: Model predicting ~50/50 for everything

**Causes**:
1. **Wrong preprocessing**: Features not encoded/scaled correctly
2. **Feature mismatch**: Different columns than training
3. **Wrong model loaded**: Loaded wrong .pkl file

**Solution**: Review preprocessing steps match training exactly.

---

## Performance Benchmarks

### Expected Performance on Test Data:

| Metric | Expected Range | Notes |
|--------|----------------|-------|
| **Accuracy** | 90-98% | Balanced dataset |
| **ROC-AUC** | 0.95-0.99 | High discriminative power |
| **Precision (ATTACK)** | 0.85-0.95 | Low false positives |
| **Recall (ATTACK)** | 0.85-0.95 | Catches most attacks |
| **F1-Score** | 0.85-0.95 | Balanced performance |

### If Performance is Lower:

- **Accuracy < 85%**: Data distribution mismatch or preprocessing error
- **High False Positives**: Model too sensitive (lower threshold)
- **High False Negatives**: Model not sensitive enough (raise threshold)

---

## Adjusting Prediction Threshold

By default, threshold = 0.5. You can adjust:

```python
# Get probabilities
proba = model.predict_proba(X_test)[:, 1]  # Probability of ATTACK

# Custom threshold (e.g., 0.7 for fewer false positives)
threshold = 0.7
custom_predictions = (proba >= threshold).astype(int)

print(f"Predictions with threshold {threshold}:")
print(np.bincount(custom_predictions))
```

**Lower threshold (e.g., 0.3)**: More sensitive, catches more attacks but more false alarms  
**Higher threshold (e.g., 0.7)**: Less sensitive, fewer false alarms but may miss attacks

---

## Saving Results for Analysis

The script saves predictions to `model_predictions.csv`:

```csv
prediction,prob_benign,prob_attack,prediction_label,actual,actual_label,correct
1,0.0234,0.9766,ATTACK,1,ATTACK,True
0,0.9854,0.0146,BENIGN,0,BENIGN,True
```

**Use this to**:
- Analyze misclassifications
- Find optimal threshold
- Generate reports for stakeholders

---

## Next Steps

1. **Run the test script**: `python test_saved_model.py`
2. **Review accuracy**: Should be >90% on held-out data
3. **Analyze errors**: Look at false positives/negatives
4. **Adjust if needed**: Retrain with more data or tune hyperparameters
5. **Deploy**: Integrate model into your DNS monitoring pipeline

---

## Quick Reference

### Load Pickle Model
```python
import pickle
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
```

### Load JSON Model
```python
import xgboost as xgb
model = xgb.XGBClassifier()
model.load_model('model.json')
```

### Make Prediction
```python
prediction = model.predict(X)  # Returns 0 or 1
probability = model.predict_proba(X)  # Returns [prob_benign, prob_attack]
```

### Interpret Results
- **0 = BENIGN**: Normal DNS traffic
- **1 = ATTACK**: DNS Abuse/Infrastructure attack detected

---

✓ **You're ready to test your model!**
