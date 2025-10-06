# protocol_model_trainer.py (Trains Layer 1 Model)
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import sys

# 1. Load the dataset (Requires protocol_anomaly_dataset.csv)
try:
    df = pd.read_csv('protocol_anomaly_dataset.csv')
except FileNotFoundError:
    print("FATAL: protocol_anomaly_dataset.csv not found. Run feature_extractor.py first.")
    sys.exit(1)

df.fillna(0, inplace=True) # Clean up any potential NaNs

# Define the features for this new model
PROTOCOL_FEATURE_COLUMNS = df.drop('label', axis=1).columns.tolist()

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

print("Training Protocol Anomaly Model (Layer 1)...")
protocol_model = RandomForestClassifier(n_estimators=100, random_state=42)
protocol_model.fit(X_train, y_train)

# 5. Save the trained model and feature list (CRITICAL for integration)
joblib.dump(protocol_model, 'protocol_anomaly_model.joblib')
joblib.dump(PROTOCOL_FEATURE_COLUMNS, 'protocol_feature_names.joblib')
print("\n--- PHASE 2 COMPLETE: Protocol Model Components Saved (2 files). ---")