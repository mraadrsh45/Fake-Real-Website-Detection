from sklearn.ensemble import RandomForestClassifier
import numpy as np
import joblib
import os

class WebsiteClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_order = [
            'url_length', 'has_https', 'num_subdomains', 'has_ip',
            'domain_length', 'tld_length', 'num_hyphens', 'num_underscores',
            'num_question_marks', 'num_equals', 'num_ampersands',
            'domain_age_days', 'has_login_form', 'has_password_input',
            'num_forms', 'num_external_links', 'num_images',
            'has_suspicious_keywords', 'has_valid_ssl', 'content_length'
        ]
        
        # Try to load existing model
        self.model_path = 'models/website_classifier.joblib'
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
    
    def preprocess_features(self, features):
        # Convert features to array in correct order
        feature_array = []
        for feature in self.feature_order:
            value = features.get(feature, 0)
            # Convert boolean to int
            if isinstance(value, bool):
                value = 1 if value else 0
            feature_array.append(value)
        return np.array(feature_array).reshape(1, -1)
    
    def predict(self, features):
        # Preprocess features
        X = self.preprocess_features(features)
        
        # Make prediction
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0][1]
        
        return {
            'is_legitimate': bool(prediction),
            'confidence': float(probability)
        }
    
    def train(self, X, y):
        """
        Train the model with new data
        X: list of feature dictionaries
        y: list of labels (0 for fake, 1 for legitimate)
        """
        # Preprocess all features
        X_processed = np.array([self.preprocess_features(x).flatten() for x in X])
        
        # Train model
        self.model.fit(X_processed, y)
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, self.model_path) 