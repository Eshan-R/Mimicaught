
from typing import Dict
from pydantic import BaseModel, HttpUrl


class URLAnalysisRequest(BaseModel):
    url: HttpUrl


class URLAnalysisResponse(BaseModel):
    url: str
    status: str
    features: Dict[str, int]
