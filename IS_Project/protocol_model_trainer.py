# protocol_model_trainer.py
# Layer 1: Protocol Anomaly Detection using CICIDS2017_sample.csv

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os
import sys

# 1️⃣ Load your local sample dataset
DATASET_PATH = "IS_Project\CICIDS2017_sample.csv"

if not os.path.exists(DATASET_PATH):
    print(f"❌ ERROR: {DATASET_PATH} not found in IS_Project folder.")
    print("Make sure the file name and location are correct.")
    sys.exit(1)

print("✅ Loading CICIDS2017_sample.csv...")
df = pd.read_csv(DATASET_PATH)
print(f"📊 Original dataset shape: {df.shape}")

# 2️⃣ Preprocess the dataset
df.fillna(0, inplace=True)

# Ensure label column name is consistent
if 'Label' in df.columns:
    df.rename(columns={'Label': 'label'}, inplace=True)

# 3️⃣ Select protocol-level relevant features
PROTOCOL_FEATURE_COLUMNS = [
    'Destination Port', 'Protocol', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Flow IAT Mean', 'Fwd IAT Mean', 'Bwd IAT Mean',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count'
]

# Keep only existing columns
PROTOCOL_FEATURE_COLUMNS = [col for col in PROTOCOL_FEATURE_COLUMNS if col in df.columns]

if not PROTOCOL_FEATURE_COLUMNS:
    print("❌ ERROR: No valid protocol-related columns found.")
    sys.exit(1)

print(f"✅ Selected {len(PROTOCOL_FEATURE_COLUMNS)} protocol-level features.")

# 4️⃣ Prepare X and y
X = df[PROTOCOL_FEATURE_COLUMNS]
y = df['label']

# Encode target: 0 = BENIGN, 1 = ATTACK
y = y.apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)

# 5️⃣ Split the data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# 6️⃣ Train the RandomForest model
print("\n🚀 Training RandomForest protocol anomaly model...")
protocol_model = RandomForestClassifier(
    n_estimators=150, random_state=42, n_jobs=-1
)
protocol_model.fit(X_train, y_train)

# 7️⃣ Evaluate the model
y_pred = protocol_model.predict(X_test)
print("\n📈 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))

# 8️⃣ Save model and features
joblib.dump(protocol_model, 'protocol_anomaly_model.joblib')
joblib.dump(PROTOCOL_FEATURE_COLUMNS, 'protocol_feature_names.joblib')

print("\n✅ Training complete! Files saved in current directory:")
print("   → protocol_anomaly_model.joblib")
print("   → protocol_feature_names.joblib")
