from pydantic import BaseModel, HttpUrl
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    url: HttpUrl

class RedirectHop(BaseModel):
    url: str
    status_code: int

class SecurityReport(BaseModel):
    is_safe: bool
    verdict: str # "green", "yellow", "red"
    threat_type: Optional[str] = None
    vendor_flags: int = 0
    total_vendors: int = 0
    domain_age_days: Optional[int] = None
    risk_score: int = 0
    suspicious_redirects: bool = False
    typosquatting_detected: bool = False
    reasons: List[str] = []

class AnalyzeResponse(BaseModel):
    original_url: str
    final_url: str
    redirect_chain: List[RedirectHop]
    screenshot_base64: str
    security: SecurityReport
