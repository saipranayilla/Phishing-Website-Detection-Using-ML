#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from flask import Flask, request, jsonify
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import re
import tldextract
import whois

app = Flask(__name__)

# Load the dataset
df = pd.read_csv("phishing_data.csv")  

# Exploring the dataset
print(df.head())
print(df.info())
print(df.describe())


# Splitting features and labels
X = df.drop(columns=['status'])  
Y = df['status']

# Splitting dataset into training and testing sets
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

# Training classifiers
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, Y_train)

# Feature extraction function
def extract_features(url):
    features = []
    features.append(len(url))  # URL length
    features.append(1 if url.startswith("https") else 0)  # HTTPS presence
    features.append(url.count('.'))  # Number of dots
    features.append(url.count('-'))  # Number of hyphens
    features.append(url.count('@'))  # '@' in URL
    features.append(url.count('?'))  # '?' in URL
    features.append(url.count('='))  # '=' in URL
    features.append(sum(url.count(char) for char in ['@', '-', '_', '=', '&', '%', '?', '#']))  # Special characters
    ext = tldextract.extract(url)
    features.append(len(ext.suffix))  # Length of TLD
    features.append(1 if ext.domain.isnumeric() else 0)  # Domain is numeric?
    try:
        domain_info = whois.whois(ext.domain + "." + ext.suffix)
        if domain_info.creation_date and domain_info.expiration_date:
            age = (domain_info.expiration_date[0] - domain_info.creation_date[0]).days
            features.append(age)  # Domain age
        else:
            features.append(0)
    except:
        features.append(0)
    suspicious_words = ["login", "verify", "bank", "secure", "account"]
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)
    expected_feature_count = 88
    while len(features) < expected_feature_count:
        features.append(0)  # Fill missing values with zeros
    return np.array(features).reshape(1, -1)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    features = extract_features(url)
    prediction = rf_model.predict(features)
    result = "Phishing Website" if prediction == 1 else "Legitimate Website"
    return jsonify({"url": url, "prediction": result})

if __name__ == '__main__':
    app.run(debug=True)


# In[ ]:




