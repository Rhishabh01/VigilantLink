# ============================================================
# Threat Intelligence Lists
# ============================================================
SUSPICIOUS_TLDS = [
    '.top', '.xyz', '.biz', '.zip', '.click', '.gq', '.tk', '.work', '.country',
    '.ml', '.cf', '.ga', '.buzz', '.surf', '.icu', '.cam', '.rest', '.monster',
    '.quest', '.sbs', '.cfd', '.lol', '.fun', '.cyou', '.bond', '.makeup',
    '.hair', '.boats', '.beauty', '.skin', '.mom', '.bar', '.autos',
]

HIGH_RISK_KEYWORDS = [
    'verify', 'login', 'bank', 'secure', 'account', 'signin', 'password',
    'wallet', 'crypto', 'auth', 'confirm', 'billing', 'payment', 'support',
]

HIGH_VALUE_TARGETS = [
    # Tech
    'google', 'amazon', 'paypal', 'github', 'microsoft', 'apple',
    'facebook', 'instagram', 'twitter', 'linkedin', 'netflix', 'spotify',
    'dropbox', 'adobe', 'zoom', 'slack', 'notion', 'discord', 'twitch',
    'reddit', 'tiktok', 'snapchat', 'pinterest', 'whatsapp', 'telegram',
    # Finance
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'capitalone',
    'americanexpress', 'venmo', 'cashapp', 'stripe', 'coinbase', 'binance',
    'robinhood', 'schwab', 'fidelity',
    # Services
    'fedex', 'ups', 'usps', 'dhl', 'walmart', 'ebay', 'bestbuy',
    'target', 'costco', 'ikea', 'homedepot',
    # Cloud/Enterprise
    'salesforce', 'atlassian', 'jira', 'confluence', 'okta', 'docusign',
    'intuit', 'turbotax', 'quickbooks',
]

SUSPICIOUS_KEYWORDS = [
    "free", "login", "update", "verify", "secure", "account", "signin",
    "confirm", "wallet", "crypto", "billing", "support", "helpdesk",
]

PHISHING_KEYWORDS = [
    # Auth/credential
    "login", "signin", "sign-in", "log-in", "verify", "password", "passwd",
    "credential", "auth", "authenticate", "authorization", "2fa", "mfa", "otp",
    # Account
    "account", "myaccount", "my-account", "profile", "dashboard", "settings",
    "suspend", "suspended", "locked", "disabled", "restricted", "unusual",
    "unauthorized", "compromised", "breach",
    # Financial
    "billing", "payment", "invoice", "refund", "subscription", "renew",
    "expire", "expired", "overdue", "outstanding", "charge", "transaction",
    "wallet", "banking", "wire", "transfer", "withdrawal",
    # Security lures
    "security", "secure", "protect", "safety", "warning", "alert", "urgent",
    "immediate", "required", "mandatory", "action-required",
    # Customer/support
    "customer", "support", "helpdesk", "help-desk", "service", "resolution",
    "ticket", "case", "dispute", "claim",
    # Crypto
    "airdrop", "giveaway", "reward", "bonus", "mining", "staking",
    "metamask", "phantom", "trustwallet", "seed-phrase", "recovery-phrase",
    # Delivery
    "tracking", "shipment", "delivery", "package", "parcel", "customs",
    "reschedule", "redelivery",
]

# Words commonly appended to brand names in phishing domains
PHISHING_APPENDERS = [
    "login", "signin", "verify", "secure", "account", "auth", "update",
    "support", "help", "helpdesk", "service", "billing", "payment",
    "security", "alert", "confirm", "online", "web", "my", "portal",
    "app", "mail", "cloud", "team", "admin", "manage", "center",
    "recovery", "restore", "wallet", "pay", "checkout", "safe",
]

# Common character substitutions used in phishing domains
HOMOGLYPH_MAP = {
    'a': ['@', '4', 'à', 'á', 'â', 'ã', 'ä'],
    'e': ['3', 'è', 'é', 'ê', 'ë'],
    'i': ['1', '!', 'l', 'í', 'ì', 'î', 'ï'],
    'o': ['0', 'ò', 'ó', 'ô', 'õ', 'ö'],
    'l': ['1', 'I', '|'],
    's': ['5', '$', 'z'],
    'g': ['9', 'q'],
    't': ['7', '+'],
    'b': ['8', 'd'],
    'n': ['m'],
    'c': ['k'],
    'u': ['v', 'ü', 'ù', 'ú', 'û'],
    'w': ['vv'],
    'rn': ['m'],
}

TRUSTED_HOSTING_DOMAINS = [
    "docs.google.com", "github.io", "pages.dev", "notion.site", "pastebin.com",
    "sites.google.com", "forms.gle", "docs.google.com", "drive.google.com",
    "appspot.com", "web.app", "firebaseapp.com",
    "vercel.app", "netlify.app", "herokuapp.com", "glitch.me",
    "replit.co", "onrender.com", "fly.dev",
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
    "sharepoint.com", "1drv.ms", "onedrive.live.com",
    "ipfs.io", "arweave.net",
]

TRUSTED_PLATFORMS = [
    "youtube.com", "google.com", "github.com", "microsoft.com",
    "cloudflare.com", "discord.com", "linkedin.com",
    "facebook.com", "twitter.com", "instagram.com",
    "reddit.com", "amazon.com", "apple.com",
    "stackoverflow.com", "wikipedia.org", "medium.com",
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

VERDICT_RED_THRESHOLD = 72
VERDICT_YELLOW_THRESHOLD = 50
PUNYCODE_MIN_SCORE = 75

# Weak signals can never independently produce yellow/red verdicts
WEAK_SIGNAL_MAX_SCORE = 30

# Trusted platform cap — uncorroborated weak signals cannot exceed yellow-1
TRUSTED_PLATFORM_CAP = 34

# ============================================================
# Weighted Scoring — Signal Penalties (Task 5)
# ============================================================
# Phase 1 (heuristic) signal values
BRAND_PENALTY_SCORE = 65
SYNERGY_PENALTY_SCORE = 60
TYPOSQUATTING_PENALTY = 65
REDIRECT_CHAIN_MAJOR_PENALTY = 20   # Cross-domain redirect hop
REDIRECT_CHAIN_MINOR_PENALTY = 5    # Same-domain redirect hop

# Phase 2 (external) signal values
SSL_CERT_VERY_NEW_PENALTY = 30      # < 1 day
SSL_CERT_NEW_PENALTY = 18           # < 10 days
SSL_CERT_RECENT_PENALTY = 10        # < 30 days
SSL_CERT_YOUNG_PENALTY = 4          # < 90 days
NEWLY_REGISTERED_PENALTY = 50       # < 14 days
RECENTLY_REGISTERED_PENALTY = 20    # < 90 days

# Weights — multipliers for each signal category
WEIGHT_HEURISTIC: float = 1.0       # Phase 1 signals at full weight
WEIGHT_SSL_AGE: float = 1.0         # SSL certificate age multiplier
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
RDAP_TIMEOUT_S: float = 1.2         # RDAP sub-task budget
GSB_TIMEOUT_S: float = 1.8          # Google Safe Browsing sub-task budget
SCREENSHOT_TIMEOUT_S: float = 15.0   # Playwright screenshot budget
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
# Hosted Phishing Detection — Deceptive query params to flag
# ============================================================
DECEPTIVE_QUERY_PARAMS = frozenset({
    "redirect", "return", "next", "goto", "target", "url", "link",
    "dest", "destination", "continue", "to", "redirect_uri", "callback",
})

# Suspicious hosted paths — login/auth pages on trusted hosting platforms
SUSPICIOUS_HOSTED_PATHS = [
    "/login", "/signin", "/sign-in", "/log-in",
    "/auth", "/authenticate", "/oauth", "/sso",
    "/password", "/credential", "/account",
    "/verify", "/verification", "/confirm", "/confirmation",
    "/billing", "/payment", "/invoice", "/checkout",
    "/wallet", "/connect-wallet", "/seed", "/recovery",
    "/secure", "/security", "/alert", "/warning",
    "/support", "/helpdesk", "/help-desk", "/ticket",
    "/update", "/upgrade", "/renew", "/reactivate",
    "/unlock", "/restore", "/recover", "/reset",
    "/admin", "/panel", "/dashboard",
]

# Weak signal patterns to filter from trusted platform reasons
WEAK_SIGNAL_PATTERNS = [
    "No metadata", "Preview unavailable", "SSL certificate",
    "Young SSL", "Recently issued", "uncertainty", "Uncertainty",
    "timed out", "Limited security data", "metadata", "screenshot",
    "commonly associated",
]

# ============================================================
# Google Safe Browsing — Threat Types & Minimum Score Overrides
# ============================================================
GSB_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "TRICK_TO_BILL",
]

# Minimum score enforced when GSB returns a match for the given threat type.
# GSB matches are high-confidence; these override weak heuristic scores.
GSB_THREAT_MIN_SCORES: dict[str, int] = {
    "MALWARE": 95,
    "SOCIAL_ENGINEERING": 90,
    "POTENTIALLY_HARMFUL_APPLICATION": 80,
    "UNWANTED_SOFTWARE": 75,
    "TRICK_TO_BILL": 85,
}

# Priority order used when multiple threat types are returned in one GSB response.
# Earlier position = higher severity = selected as the canonical gsbt value.
GSB_THREAT_PRIORITY = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "UNWANTED_SOFTWARE",
    "TRICK_TO_BILL",
]

# ============================================================
# PhishTank Offline Intelligence
# ============================================================
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.json"
PHISHTANK_REFRESH_INTERVAL_S = 1800  # 30 minutes
PHISHTANK_URL_PENALTY = 95
PHISHTANK_DOMAIN_PENALTY = 60