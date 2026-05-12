from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional
from enum import IntEnum


class AnalysisStatus(IntEnum):
    """Integer status enum — saves bytes over string-based status."""
    PENDING = 0    # Phase 2 not started or in progress
    PARTIAL = 1    # Phase 1 complete, Phase 2 running
    COMPLETE = 2   # All phases done


class AnalyzeRequest(BaseModel):
    url: HttpUrl


class ScanRequest(BaseModel):
    url: str
    source_url: Optional[str] = None


class RedirectHop(BaseModel):
    url: str
    status_code: int


class SecurityReport(BaseModel):
    is_safe: bool
    verdict: str  # "green", "yellow", "red"
    threat_type: Optional[str] = None
    vendor_flags: int = 0
    total_vendors: int = 0
    ssl_cert_age_days: Optional[int] = None
    risk_score: int = 0
    suspicious_redirects: bool = False
    typosquatting_detected: bool = False
    reasons: List[str] = []
    gsb_matched: bool = False
    gsb_threat_type: Optional[str] = None


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


# ============================================================
# Compact JSON Models (Production Wire Format)
# ============================================================

class CompactHop(BaseModel):
    """Minimized redirect hop — saves bytes on wire."""
    u: str = Field(description="URL")
    c: int = Field(description="HTTP status code")


class CompactSecurity(BaseModel):
    """Minimized security report."""
    safe: bool
    v: str = Field(description="verdict: green|yellow|red")
    rs: int = Field(description="risk_score 0-100")
    tt: Optional[str] = Field(None, description="threat_type")
    vf: int = Field(0, description="vendor_flags")
    tv: int = Field(0, description="total_vendors")
    age: Optional[int] = Field(None, description="ssl_cert_age_days")
    sr: bool = Field(False, description="suspicious_redirects")
    ts: bool = Field(False, description="typosquatting_detected")
    r: List[str] = Field(default_factory=list, description="reasons")
    gsb: bool = Field(False, description="google_safe_browsing_matched")
    gsbt: Optional[str] = Field(None, description="gsb_threat_type: MALWARE|SOCIAL_ENGINEERING|UNWANTED_SOFTWARE|POTENTIALLY_HARMFUL_APPLICATION")


class CompactResponse(BaseModel):
    """
    Minimized wire format for extension ↔ backend communication.
    Uses short field names to reduce payload size.
    """
    s: int = Field(description="stage: 0=pending, 1=partial, 2=complete")
    id: str = Field(description="request_id")
    url: Optional[str] = Field(None, description="original_url")
    furl: Optional[str] = Field(None, description="final_url")
    hops: List[CompactHop] = Field(default_factory=list)
    t: Optional[str] = Field(None, description="title")
    d: Optional[str] = Field(None, description="description")
    img: Optional[str] = Field(None, description="preview_image_url")
    fav: Optional[str] = Field(None, description="favicon_url")
    ss: Optional[str] = Field(None, description="screenshot_base64")
    sec: Optional[CompactSecurity] = None
    ms: int = Field(0, description="duration_ms")