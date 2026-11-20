
from fastapi import FastAPI, HTTPException
from api.schemas import URLAnalysisRequest, URLAnalysisResponse
from src.features.url_analysis import extract_features

app = FastAPI(
    title="Mimicaught API",
    description="AI-powered phishing and deepfake detection backend",
    version="1.0.0"
)


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
    try:
        url = str(request.url)

        features = extract_features(url)

        return {
            "url": url,
            "status": "features_extracted",
            "features": features
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"URL analysis failed: {str(error)}"
        )
