from flask import Flask, render_template, request, redirect, url_for, session
import joblib
import os
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import RandomForestClassifier
from feature_extractor import extract_features

app = Flask(__name__)
app.secret_key = "securekey123"  # needed for session storage

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

        if not is_valid_url(url):
            session["error"] = "❌ Invalid URL Format! Example: google.com"
            return redirect(url_for("index"))

        normalized_url = normalize_url(url)
        features = extract_features(normalized_url)

        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0][1]
        risk_score = round(float(proba) * 100, 2)

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

        # store one-time result in session
        session["result"] = result
        session["risk_score"] = risk_score
        session["url"] = normalized_url
        session["level"] = level

        return redirect(url_for("index"))

    # For GET request (after redirect)
    result = session.pop("result", None)
    risk_score = session.pop("risk_score", None)
    url_text = session.pop("url", None)
    level = session.pop("level", None)
    error = session.pop("error", None)

    return render_template("index.html", result=result, risk_score=risk_score, url=url_text, level=level, error=error)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
