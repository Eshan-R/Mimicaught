import logging, time
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from api.schemas import URLAnalysisRequest, URLAnalysisResponse
from src.features.url_analysis import extract_features, validate_public_url, UnsafeURLError, FEATURE_COLUMNS
from contextlib import asynccontextmanager

logger = logging.getLogger("mimicaught")
models = {}

SAFE_BELOW = 0.4
PHISHING_ABOVE = 0.7

@asynccontextmanager
async def lifespan(app):
    try:
        models["url"] = joblib.load("models_saved/phishing_xgb_model.pkl")
    except FileNotFoundError:
        models["url"] = None
    yield

app = FastAPI(
    title="Mimicaught API",
    description="AI-powered phishing and deepfake detection backend",
    version="1.0.0",
    lifespan = lifespan
)

def to_verdict(prob: float) -> str:
    if prob < SAFE_BELOW:
        return "safe"
    if prob > PHISHING_ABOVE:
        return "phishing"
    return "phishing"

@app.get("/")
def home():
    return {
        "message": "Welcome to Mimicaught Backend!",
        "status": "Running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "backend": "Mimicaught API"
    }


@app.post("/analyze/url", response_model=URLAnalysisResponse)
def analyze_url(request: URLAnalysisRequest):
    url = str(request.url)

    try:
        validate_public_url(url)
    except UnsafeURLError:
        raise HTTPException(status_code=400, detail="This URL cannot be analysed")

    if models.get("url") is None:
        raise HTTPException(status_code=503, detail="Model not available")

    start = time.perf_counter()
    
    try:
        features = extract_features(url)
    except Exception:
        logger.exception("URL analysis failed")          # full detail stays in the server log
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")

    try:
        X = pd.DataFrame([features])[FEATURE_COLUMNS]
        prob = float(models["url"].predict_proba(X)[0, 1])
    except Exception:
        logger.exception("Prediction Failed")
        raise HTTPException(status_code=500, detail="Analysis failed. Please Try again")

    return {
        "url": url,
        "status": "features_extracted",
        "risk_score": round(prob, 4),
        "verdict": to_verdict(prob),
        "features": features,
        "latency_ms": int((time.perf_counter() - start) * 1000),
    }