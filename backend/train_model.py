import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

def load_and_preprocess_data(filepath):
    """Load and preprocess NSL-KDD dataset"""
    
    # Column names for NSL-KDD dataset
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
    ]
    
    print("Loading dataset...")
    df = pd.read_csv(filepath, names=columns)
    
    # Remove difficulty column
    df = df.drop('difficulty', axis=1, errors='ignore')
    
    # Convert attack types to binary (normal vs attack)
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    print(f"Dataset shape: {df.shape}")
    print(f"Normal traffic: {(df['label'] == 0).sum()}")
    print(f"Attack traffic: {(df['label'] == 1).sum()}")
    
    return df

def encode_features(df):
    """Encode categorical features"""
    
    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for col in categorical_columns:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le
    
    return df, label_encoders

def train_model(train_path='data/KDDTrain+.txt', test_path='data/KDDTest+.txt'):
    """Train the intrusion detection model"""
    
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Load datasets separately
    train_df = load_and_preprocess_data(train_path)
    test_df  = load_and_preprocess_data(test_path)

    # Encode categorical features using only training data
    train_df, label_encoders = encode_features(train_df)

    # Apply same encoders to test data (important!)
    for col, le in label_encoders.items():
        test_df[col] = le.transform(test_df[col].astype(str))
    
    # Split into X and y
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train XGBoost
    print("\nTraining XGBoost model...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X_train_scaled, y_train)

    # Evaluate on REAL test data
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n{'='*50}")
    print(f"Model Accuracy (True NSL Test Set): {accuracy * 100:.2f}%")
    print(f"{'='*50}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save everything
    print("\nSaving model and preprocessing objects...")
    joblib.dump(model, 'models/intrusion_model.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
    joblib.dump(label_encoders, 'models/label_encoders.pkl')
    joblib.dump(list(X_train.columns), 'models/feature_names.pkl')

    print("✅ Model training completed and saved successfully!")


if __name__ == "__main__":
    train_model()