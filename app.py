from flask import Flask, render_template, request, redirect, url_for
import joblib
import os
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import RandomForestClassifier
from feature_extractor import extract_features

app = Flask(__name__)

def train_model():
    dataset = pd.read_csv("phishing_dataset.csv")
    X, y = [], []

    for index, row in dataset.iterrows():
        X.append(extract_features(row["url"]))
        y.append(row["label"])

    model = RandomForestClassifier()
    model.fit(np.array(X), np.array(y))
    joblib.dump(model, "model.pkl")
    print("Model trained & saved as model.pkl")
    return model

# Load model if exists, otherwise train
model = joblib.load("model.pkl") if os.path.exists("model.pkl") else train_model()


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def is_valid_url(url):
    pattern = re.compile(r"^(https?:\/\/)?([\w\-]+\.)+[\w\-]{2,}$")
    return bool(pattern.match(url))


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()

        # URL format validation
        if not is_valid_url(url):
            return render_template("index.html", error="❌ Invalid URL Format! Enter something like example.com or https://google.com")

        normalized_url = normalize_url(url)
        features = extract_features(normalized_url)

        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0][1]
        risk_score = round(float(proba) * 100, 2)

        # RISK LEVEL CATEGORIES
        if risk_score >= 90:
            level = "🚨 Extremely Dangerous"
        elif risk_score >= 75:
            level = "🔴 High Risk"
        elif risk_score >= 50:
            level = "🟠 Medium Risk"
        elif risk_score >= 25:
            level = "🟡 Low Risk"
        else:
            level = "🟢 Safe"

        result = "⚠ Phishing Website (Unsafe)" if prediction == 1 else "✔ Legitimate Website (Safe)"

        # Return data to frontend
        return render_template("index.html", result=result, risk_score=risk_score, url=normalized_url, level=level)

    # GET Request (first load or refresh) = clean UI
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
