import joblib
import numpy as np
import pandas as pd
from typing import Dict, List
import os

class IntrusionDetectionModel:
    """
    Intrusion Detection System Model
    Loads trained model and makes predictions
    """
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.feature_names = None
        self.is_loaded = False
    
    def load_model(self):
        """Load the trained model and preprocessing objects"""
        try:
            model_path = 'models/intrusion_model.pkl'
            scaler_path = 'models/scaler.pkl'
            encoders_path = 'models/label_encoders.pkl'
            features_path = 'models/feature_names.pkl'
            
            # Check if files exist
            if not all(os.path.exists(p) for p in [model_path, scaler_path, encoders_path, features_path]):
                raise FileNotFoundError("Model files not found. Please train the model first.")
            
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoders = joblib.load(encoders_path)
            self.feature_names = joblib.load(features_path)
            self.is_loaded = True
            
            print("Model loaded successfully!")
            
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            raise
    
    def preprocess_input(self, data: Dict) -> np.ndarray:
        """Preprocess input data for prediction"""
        
        if not self.is_loaded:
            raise Exception("Model not loaded. Call load_model() first.")
        
        # Create DataFrame from input
        df = pd.DataFrame([data])
        
        # Encode categorical features
        categorical_columns = ['protocol_type', 'service', 'flag']
        for col in categorical_columns:
            if col in df.columns and col in self.label_encoders:
                le = self.label_encoders[col]
                # Handle unknown categories
                df[col] = df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
                df[col] = le.transform(df[col].astype(str))
        
        # Ensure all features are present and in correct order
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        df = df[self.feature_names]
        
        # Scale features
        scaled_data = self.scaler.transform(df)
        
        return scaled_data
    
    def predict(self, data: Dict) -> Dict:
        """
        Make prediction on input data
        
        Args:
            data: Dictionary containing network traffic features
            
        Returns:
            Dictionary with prediction result and confidence
        """
        
        if not self.is_loaded:
            self.load_model()
        
        # Preprocess input
        processed_data = self.preprocess_input(data)
        
        # Make prediction
        prediction = self.model.predict(processed_data)[0]
        prediction_proba = self.model.predict_proba(processed_data)[0]
        
        # Prepare result
        result = {
            "prediction": "Attack" if prediction == 1 else "Normal",
            "is_intrusion": bool(prediction == 1),
            "confidence": float(prediction_proba[prediction] * 100),
            "attack_probability": float(prediction_proba[1] * 100),
            "normal_probability": float(prediction_proba[0] * 100)
        }
        
        return result
    
    def predict_batch(self, data_list: List[Dict]) -> List[Dict]:
        """
        Make predictions on multiple data points
        
        Args:
            data_list: List of dictionaries containing network traffic features
            
        Returns:
            List of prediction results
        """
        
        if not self.is_loaded:
            self.load_model()
        
        results = []
        for data in data_list:
            result = self.predict(data)
            results.append(result)
        
        return results

# Global model instance
ids_model = IntrusionDetectionModel()