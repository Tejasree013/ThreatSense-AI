import joblib
import os

BASE_DIR = os.path.dirname(__file__)

model = joblib.load(
    os.path.join(BASE_DIR, "models", "model.pkl")
)

vectorizer = joblib.load(
    os.path.join(BASE_DIR, "models", "vectorizer.pkl")
)


def detect_news(news_text):
    transformed = vectorizer.transform([news_text])

    prediction = model.predict(transformed)[0]

    confidence = model.predict_proba(transformed).max()
    confidence = round(confidence * 100, 2)

    if prediction == 1:
        result = "REAL NEWS"
    else:
        result = "FAKE NEWS"

    if confidence >= 85:
        risk = "HIGH CONFIDENCE"
    elif confidence >= 65:
        risk = "MEDIUM CONFIDENCE"
    else:
        risk = "LOW CONFIDENCE"

    return result, confidence, risk