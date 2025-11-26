from flask import Flask, render_template, request
import joblib
from feature_extractor import extract_features

app = Flask(__name__)

model = joblib.load("model.pkl")

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    reasons = []
    risk_score = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            normalized_url = normalize_url(url)
            features = extract_features(normalized_url)
            prediction = model.predict([features])[0]

            try:
                proba = model.predict_proba([features])[0][1]
                risk_score = round(float(proba) * 100, 2)
            except:
                risk_score = None

            if prediction == 1:
                result = "⚠ Phishing Website (Unsafe)"
            else:
                result = "✔ Legitimate Website (Safe)"

    return render_template("index.html", result=result, url=url, risk_score=risk_score)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
