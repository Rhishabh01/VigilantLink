from pydantic import BaseModel, HttpUrl
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    url: HttpUrl

class RedirectHop(BaseModel):
    url: str
    status_code: int

class SecurityReport(BaseModel):
    is_safe: bool
    verdict: str  # "green", "yellow", "red"
    threat_type: Optional[str] = None
    vendor_flags: int = 0
    total_vendors: int = 0
    domain_age_days: Optional[int] = None
    risk_score: int = 0
    suspicious_redirects: bool = False
    typosquatting_detected: bool = False
    reasons: List[str] = []

class ProgressiveResponse(BaseModel):
    """Response model supporting staged progressive delivery."""
    stage: int  # 1 = instant heuristics, 2 = deep scan complete
    request_id: str
    original_url: str
    final_url: Optional[str] = None
    redirect_chain: List[RedirectHop] = []

    # Metadata (stage 1)
    title: Optional[str] = None
    description: Optional[str] = None
    preview_image_url: Optional[str] = None
    favicon_url: Optional[str] = None

    # Security (partial in stage 1, complete in stage 2)
    security: SecurityReport

    # Screenshot (stage 3 enrichment, usually null)
    screenshot_base64: Optional[str] = None

    # Performance metadata
    duration_ms: int = 0

# Keep legacy model for backward compatibility with cache
class AnalyzeResponse(BaseModel):
    original_url: str
    final_url: str
    redirect_chain: List[RedirectHop]
    screenshot_base64: str
    security: SecurityReport
    title: Optional[str] = None
    description: Optional[str] = None
    preview_image_url: Optional[str] = None
