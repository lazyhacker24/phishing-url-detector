import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
from feature_extractor import extract_features

dataset = pd.read_csv("phishing_dataset.csv")  

X = []
y = []

for index, row in dataset.iterrows():
    url = row["url"]
    label = row["label"]  # 1 = phishing, 0 = legitimate
    X.append(extract_features(url))
    y.append(label)

X = np.array(X)
y = np.array(y)

x_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier()
model.fit(x_train, y_train)

y_pred = model.predict(x_test)
accuracy = accuracy_score(y_test, y_pred)

print("Model Training Complete!")
print("Accuracy:", accuracy)

joblib.dump(model, "model.pkl")
print("Model saved as model.pkl")
