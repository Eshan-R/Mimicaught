
from typing import Dict
from pydantic import BaseModel, HttpUrl


class URLAnalysisRequest(BaseModel):
    url: HttpUrl


class URLAnalysisResponse(BaseModel):
    url: str
    status: str
    risk_score: float
    features: Dict[str, int]
    verdict: str
    latency_ms: int | None = None
