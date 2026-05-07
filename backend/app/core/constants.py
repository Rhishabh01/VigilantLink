# ============================================================
# Threat Intelligence Lists
# ============================================================
SUSPICIOUS_TLDS = ['.top', '.xyz', '.biz', '.zip', '.click', '.gq', '.tk', '.work', '.country']
HIGH_RISK_KEYWORDS = ['verify', 'login', 'bank', 'secure', 'account']
HIGH_VALUE_TARGETS = ['google', 'amazon', 'paypal', 'github', 'microsoft', 'apple']
SUSPICIOUS_KEYWORDS = ["free", "login", "update", "verify", "secure", "account"]
PHISHING_KEYWORDS = ["login", "verify", "password", "account", "security", "wallet", "banking", "auth"]
TRUSTED_HOSTING_DOMAINS = ["docs.google.com", "github.io", "pages.dev", "notion.site", "pastebin.com"]

# ============================================================
# Scoring Thresholds
# ============================================================
NEW_DOMAIN_THRESHOLD_DAYS = 30
NEWLY_REGISTERED_DAYS = 14
RECENTLY_REGISTERED_DAYS = 90
MAX_REDIRECT_HOPS_FREE = 3
SEVERE_VENDOR_FLAGS_THRESHOLD = 5

VERDICT_RED_THRESHOLD = 71
VERDICT_YELLOW_THRESHOLD = 36
PUNYCODE_MIN_SCORE = 75

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
NEWLY_REGISTERED_PENALTY = 40       # Domain age < 14 days
RECENTLY_REGISTERED_PENALTY = 20    # Domain age < 90 days

# Weights — multipliers for each signal category
WEIGHT_HEURISTIC: float = 1.0       # Phase 1 signals at full weight
WEIGHT_RDAP_AGE: float = 1.0        # Domain age penalty multiplier
WEIGHT_VT: float = 1.0              # VirusTotal vendor flags multiplier
WEIGHT_REDIRECT_DEPTH: float = 1.0  # Redirect chain penalty multiplier

# Uncertainty penalty when external sources timeout (Task 2.4)
# Formula: U = UNCERTAINTY_PENALTY × (timed_out_sources / total_sources)
# Max penalty = 15 (both RDAP + VT timeout)
UNCERTAINTY_PENALTY: int = 15

# ============================================================
# Fallbacks
# ============================================================
DEFAULT_DOMAIN_AGE_DAYS = 3000
TOTAL_VENDORS_COUNT = 70

# ============================================================
# Deadlines & Budgets
# ============================================================
GLOBAL_DEADLINE_S: float = 2.0      # Total budget for Phase 1 + Phase 2
PHASE1_DEADLINE_S: float = 0.5      # Phase 1 target
RDAP_TIMEOUT_S: float = 0.8         # RDAP sub-task budget
VT_TIMEOUT_S: float = 1.5           # VirusTotal sub-task budget
GSB_TIMEOUT_S: float = 1.8          # Google Safe Browsing sub-task budget
SCREENSHOT_TIMEOUT_S: float = 5.0   # Playwright screenshot budget
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ============================================================
# Resource Limits
# ============================================================
MAX_CONCURRENT_SCREENSHOTS: int = 3  # Semaphore value for Playwright pages

# ============================================================
# URL Normalization — Tracking params to strip
# ============================================================
TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "ref", "source",
})

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