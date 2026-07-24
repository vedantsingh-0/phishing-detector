from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd

from feature_extractor import extract_features

app = FastAPI(title="Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load("phishing_model.pkl")
feature_columns = joblib.load("feature_columns.pkl")


class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {"message": "Phishing Detector API is running"}


@app.post("/predict")
def predict(request: URLRequest):
    raw_features = extract_features(request.url)
    ordered_values = [raw_features[col] for col in feature_columns]
    X = pd.DataFrame([ordered_values], columns=feature_columns)

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    classes = list(model.classes_)
    phishing_index = classes.index(-1)
    legit_index = classes.index(1)

    confidence = float(max(probabilities))
    result = "Legitimate" if prediction == 1 else "Phishing"

    return {
        "url": request.url,
        "prediction": result,
        "confidence": round(confidence * 100, 2),
        "phishing_probability": round(float(probabilities[phishing_index]) * 100, 2),
        "legitimate_probability": round(float(probabilities[legit_index]) * 100, 2),
        "features_used": raw_features,
    }
