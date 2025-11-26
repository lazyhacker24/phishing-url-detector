from flask import Flask, render_template, request
import joblib
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from feature_extractor import extract_features

app = Flask(__name__)

def train_model():
    dataset = pd.read_csv("phishing_dataset.csv")
    X = []
    y = []

    for index, row in dataset.iterrows():
        X.append(extract_features(row["url"]))
        y.append(row["label"])

    X = np.array(X)
    y = np.array(y)

    model = RandomForestClassifier()
    model.fit(X, y)
    joblib.dump(model, "model.pkl")
    print("Model Trained in Render & Saved as model.pkl")
    return model

# Load existing model or auto train if missing
if os.path.exists("model.pkl"):
    model = joblib.load("model.pkl")
else:
    model = train_model()

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    risk_score = None
    risk_level = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        normalized_url = normalize_url(url)
        features = extract_features(normalized_url)

        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0][1]
        risk_score = round(float(proba) * 100, 2)

        # Assign risk category
        if risk_score <= 25:
            risk_level = "🟢 Low Risk"
        elif risk_score <= 50:
            risk_level = "🟡 Medium Risk"
        elif risk_score <= 75:
            risk_level = "🟠 High Risk"
        else:
            risk_level = "🔴 Extreme Risk"

        # Prediction based text
        if prediction == 1:
            result = "⚠ Phishing Website (Unsafe)"
        else:
            result = "✔ Legitimate Website (Safe)"

    return render_template("index.html", result=result, url=url, risk_score=risk_score, risk_level=risk_level)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
