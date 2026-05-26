# ============================================================
# Threat Intelligence Lists
# ============================================================
SUSPICIOUS_TLDS = ['.top', '.xyz', '.biz', '.zip', '.click', '.gq', '.tk', '.work', '.country']
HIGH_RISK_KEYWORDS = ['verify', 'login', 'bank', 'secure', 'account']
HIGH_VALUE_TARGETS = ['google', 'amazon', 'paypal', 'github', 'microsoft', 'apple']
SUSPICIOUS_KEYWORDS = ["free", "login", "update", "verify", "secure", "account"]
PHISHING_KEYWORDS = ["login", "verify", "password", "account", "security", "wallet", "banking", "auth"]
TRUSTED_HOSTING_DOMAINS = ["docs.google.com", "github.io", "pages.dev", "notion.site", "pastebin.com"]
TRUSTED_PLATFORMS = [
    "youtube.com", "google.com", "github.com", "microsoft.com",
    "cloudflare.com", "discord.com", "linkedin.com",
]
SAFE_DOMAINS = [
    "accounts.google.com",
]

# ============================================================
# Scoring Thresholds
# ============================================================
NEW_DOMAIN_THRESHOLD_DAYS = 30
SSL_CERT_VERY_NEW_DAYS = 2
SSL_CERT_NEW_DAYS = 10
SSL_CERT_RECENT_DAYS = 30
SSL_CERT_YOUNG_DAYS = 90
NEWLY_REGISTERED_DAYS = 14
RECENTLY_REGISTERED_DAYS = 90
MAX_REDIRECT_HOPS_FREE = 3
SEVERE_VENDOR_FLAGS_THRESHOLD = 5

# VT low-confidence suppression — vendor_flags below this + no corroboration = zero contribution
VT_LOW_CONFIDENCE_THRESHOLD = 2
# Minimum vendor flags to count as corroboration for trusted platforms
CORROBORATION_MIN_VENDOR_FLAGS = 3

VERDICT_RED_THRESHOLD = 65
VERDICT_YELLOW_THRESHOLD = 35
PUNYCODE_MIN_SCORE = 75

# Trusted platform cap — uncorroborated weak signals cannot exceed yellow-1
TRUSTED_PLATFORM_CAP = 34

# ============================================================
# Weighted Scoring — Signal Penalties (Task 5)
# ============================================================
# Phase 1 (heuristic) signal values
BRAND_PENALTY_SCORE = 50
SYNERGY_PENALTY_SCORE = 40
TYPOSQUATTING_PENALTY = 50
REDIRECT_CHAIN_MAJOR_PENALTY = 20   # Cross-domain redirect hop
REDIRECT_CHAIN_MINOR_PENALTY = 5    # Same-domain redirect hop

# Phase 2 (external) signal values
VENDOR_FLAG_PENALTY = 40            # Applied when vendor_flags >= 2
SSL_CERT_VERY_NEW_PENALTY = 30      # < 1 day
SSL_CERT_NEW_PENALTY = 18           # < 10 days
SSL_CERT_RECENT_PENALTY = 10        # < 30 days
SSL_CERT_YOUNG_PENALTY = 4          # < 90 days
NEWLY_REGISTERED_PENALTY = 50       # < 14 days
RECENTLY_REGISTERED_PENALTY = 20    # < 90 days

# Weights — multipliers for each signal category
WEIGHT_HEURISTIC: float = 1.0       # Phase 1 signals at full weight
WEIGHT_SSL_AGE: float = 1.0         # SSL certificate age multiplier
WEIGHT_VT: float = 1.0              # VirusTotal vendor flags multiplier
WEIGHT_REDIRECT_DEPTH: float = 1.0  # Redirect chain penalty multiplier
WEIGHT_RDAP_AGE: float = 1.0        # RDAP domain age multiplier

# Uncertainty penalty when external sources timeout (Task 2.4)
# Formula: U = UNCERTAINTY_PENALTY × (timed_out_sources / total_sources)
# Max penalty = 15 (both SSL + VT timeout)
UNCERTAINTY_PENALTY: int = 15

# ============================================================
# Fallbacks
# ============================================================
DEFAULT_DOMAIN_AGE_DAYS = 3000

# ============================================================
# Deadlines & Budgets
# ============================================================
GLOBAL_DEADLINE_S: float = 2.0      # Total budget for Phase 1 + Phase 2
PHASE1_DEADLINE_S: float = 0.5      # Phase 1 target
SSL_CERT_TIMEOUT_S: float = 1.2     # SSL Certificate inspection budget
VT_TIMEOUT_S: float = 1.5           # VirusTotal sub-task budget
RDAP_TIMEOUT_S: float = 1.2         # RDAP sub-task budget
GSB_TIMEOUT_S: float = 1.8          # Google Safe Browsing sub-task budget
SCREENSHOT_TIMEOUT_S: float = 15.0   # Playwright screenshot budget
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ============================================================
# Resource Limits
# ============================================================
MAX_CONCURRENT_SCREENSHOTS: int = 2  # Aggressively limited to prevent OOM in Railway

# ============================================================
# URL Normalization — Tracking params to strip
# ============================================================
TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "ref", "source",
})

# ============================================================
# Hosted Phishing Detection — Deceptive query params to flag
# ============================================================
DECEPTIVE_QUERY_PARAMS = frozenset({
    "redirect", "return", "next", "goto", "target", "url", "link",
    "dest", "destination", "continue", "to", "redirect_uri", "callback",
})

# Suspicious hosted paths — login/auth pages on trusted hosting platforms
SUSPICIOUS_HOSTED_PATHS = [
    "/login", "/signin", "/auth", "/authenticate",
    "/password", "/credential", "/account",
]

# Weak signal patterns to filter from trusted platform reasons
WEAK_SIGNAL_PATTERNS = [
    "No metadata", "Preview unavailable", "SSL certificate",
    "Young SSL", "Recently issued", "uncertainty", "Uncertainty",
    "timed out", "Limited security data", "metadata", "screenshot",
]

# ============================================================
# Google Safe Browsing — Threat Types & Minimum Score Overrides
# ============================================================
GSB_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Minimum score enforced when GSB returns a match for the given threat type.
# GSB matches are high-confidence; these override weak heuristic scores.
GSB_THREAT_MIN_SCORES: dict[str, int] = {
    "MALWARE": 95,
    "SOCIAL_ENGINEERING": 90,
    "POTENTIALLY_HARMFUL_APPLICATION": 80,
    "UNWANTED_SOFTWARE": 75,
}

# Priority order used when multiple threat types are returned in one GSB response.
# Earlier position = higher severity = selected as the canonical gsbt value.
GSB_THREAT_PRIORITY = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "UNWANTED_SOFTWARE",
]