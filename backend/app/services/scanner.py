"""
Scanner: Heuristic analysis engine + external scan orchestration.

Tier 1 (CPU): Pure heuristics — typosquatting, punycode, TLD/keyword synergy,
              homoglyph detection, brand appender detection, char substitution.
Tier 2 (Network): RDAP + GSB in parallel (asyncwhois removed).
"""

import asyncio
import logging
import os
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..core.constants import (
    HIGH_RISK_KEYWORDS, HIGH_VALUE_TARGETS, SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS, DEFAULT_DOMAIN_AGE_DAYS,
    GSB_API_URL, GSB_THREAT_TYPES, GSB_THREAT_PRIORITY, GSB_TIMEOUT_S,
    SSL_CERT_TIMEOUT_S, RDAP_TIMEOUT_S, NEWLY_REGISTERED_DAYS,
    RECENTLY_REGISTERED_DAYS, PHISHTANK_FEED_URL, PHISHTANK_REFRESH_INTERVAL_S,
    TRUSTED_PLATFORMS, PHISHING_APPENDERS, HOMOGLYPH_MAP,
)
from .rdap_client import fetch_domain_age_rdap
from ..core.logging import get_logger

logger = get_logger("VigilantLink")


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# ============================================================
# Advanced Impersonation Detection
# ============================================================

def _strip_tld(domain: str) -> str:
    """Extract the registrable name without TLD. e.g. 'paypa1.xyz' -> 'paypa1'"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _check_homoglyph_substitution(domain_name: str, brand: str) -> Optional[str]:
    """
    Detects character substitution attacks.
    e.g. paypa1.com (l->1), g00gle.com (o->0), amaz0n.com (o->0)
    """
    if len(domain_name) != len(brand):
        return None

    diffs = []
    for i, (dc, bc) in enumerate(zip(domain_name, brand)):
        if dc != bc:
            diffs.append((i, dc, bc))

    if not diffs or len(diffs) > 2:
        return None

    for _, dc, bc in diffs:
        # Check if the substituted char is a known homoglyph for the brand char
        if bc in HOMOGLYPH_MAP and dc in HOMOGLYPH_MAP[bc]:
            continue
        # Check single-char visual confusion (reverse direction)
        if dc in HOMOGLYPH_MAP and bc in HOMOGLYPH_MAP[dc]:
            continue
        # Not a recognized substitution
        return None

    subs = ", ".join(f"'{bc}'→'{dc}'" for _, dc, bc in diffs)
    return f"Character substitution impersonating {brand} ({subs})"


def _normalize_homoglyphs(text: str) -> str:
    """Normalize common homoglyph substitutions back to ascii for comparison."""
    replacements = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's'}
    return ''.join(replacements.get(c, c) for c in text)


def _check_brand_appender(domain_name: str, brand: str) -> Optional[str]:
    """
    Detects brand + phishing word patterns.
    e.g. paypal-login.com, google-verify.net, amazon-security.xyz, amaz0n-security.xyz
    """
    # Strip separators for comparison
    clean = domain_name.replace('-', '').replace('_', '').replace('.', '')

    # Check both raw and homoglyph-normalized versions
    normalized = _normalize_homoglyphs(clean)
    matched_brand = brand in clean or brand in normalized

    if not matched_brand:
        return None

    # The domain contains the brand — check if phishing words are appended/prepended
    remainder = normalized.replace(brand, '', 1) if brand in normalized else clean.replace(brand, '', 1)
    if not remainder:
        return None

    for appender in PHISHING_APPENDERS:
        if appender in remainder:
            was_obfuscated = brand not in clean and brand in normalized
            prefix = "Obfuscated brand" if was_obfuscated else "Brand name"
            return f"{prefix} '{brand}' combined with phishing keyword '{appender}'"

    return None


def _check_repeated_or_missing_chars(domain_name: str, brand: str) -> Optional[str]:
    """
    Detects repeated/missing character attacks.
    e.g. gooogle.com (extra o), amazn.com (missing a), paypall.com (extra l)
    """
    if abs(len(domain_name) - len(brand)) not in (1, 2):
        return None

    # Check character frequency similarity
    from collections import Counter
    dc = Counter(domain_name)
    bc = Counter(brand)

    diff_chars = set()
    for ch in set(list(dc.keys()) + list(bc.keys())):
        delta = abs(dc.get(ch, 0) - bc.get(ch, 0))
        if delta > 0:
            diff_chars.add(ch)

    # If only 1-2 characters differ in count, it's likely a repeat/omission attack
    if len(diff_chars) <= 2:
        # Verify with edit distance as confirmation
        dist = levenshtein_distance(domain_name, brand)
        if dist <= 2:
            if len(domain_name) > len(brand):
                return f"Repeated character attack impersonating {brand}"
            else:
                return f"Missing character attack impersonating {brand}"

    return None


def detect_impersonation(domain: str, tld: str = "", has_suspicious_keywords: bool = False) -> Dict[str, Any]:
    """
    Advanced impersonation detection combining multiple techniques with
    contextual confidence scoring. Edit-distance alone is treated as weak;
    escalation requires phishing behavior context (auth keywords, suspicious TLDs,
    redirects, hosted phishing behavior, credential collection indicators).

    1. Levenshtein distance (edit distance 1 or 2)
    2. Homoglyph/character substitution
    3. Brand + phishing word appenders
    4. Repeated/missing character attacks

    Returns detection result with contextual_confidence (0.0-1.0).
    confidence >= 0.5 is treated as a strong phishing signal.
    """
    parts = domain.split('.')
    if len(parts) > 2:
        root_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = domain

    domain_name = _strip_tld(root_domain)

    # Pre-compute phishing context
    tld_is_suspicious = tld in SUSPICIOUS_TLDS if tld else False
    domain_has_auth_keywords = any(kw in domain_name for kw in
        ['login', 'signin', 'verify', 'auth', 'secure', 'account',
         'password', 'credential', '2fa', 'mfa', 'otp', 'wallet'])
    domain_has_any_keywords = domain_has_auth_keywords or has_suspicious_keywords

    best = {
        "detected": False,
        "brand": None,
        "reason": None,
        "technique": None,
        "severity": "none",
        "contextual_confidence": 0.0,
    }

    for target in HIGH_VALUE_TARGETS:
        target_domain = f"{target}.com" if '.' not in target else target
        target_name = _strip_tld(target_domain)

        # Skip exact matches
        if root_domain == target_domain or domain_name == target_name:
            continue

        techniques = []

        # 1. Homoglyph substitution (visual match — weak without phishing context)
        sub_reason = _check_homoglyph_substitution(domain_name, target_name)
        if sub_reason:
            base = 0.40
            if tld_is_suspicious: base += 0.25
            if domain_has_auth_keywords: base += 0.25
            elif domain_has_any_keywords: base += 0.10
            techniques.append({
                "reason": sub_reason,
                "technique": "homoglyph",
                "confidence": min(base, 1.0),
            })

        # 2. Distance-1 Levenshtein
        dist = levenshtein_distance(root_domain, target_domain)
        if dist == 1:
            base = 0.40
            if tld_is_suspicious: base += 0.25
            if domain_has_auth_keywords: base += 0.25
            elif domain_has_any_keywords: base += 0.10
            techniques.append({
                "reason": f"Typosquatting: 1 edit away from {target}",
                "technique": "levenshtein",
                "confidence": min(base, 1.0),
            })

        # 3. Brand + phishing appender
        app_reason = _check_brand_appender(domain_name, target_name)
        if app_reason:
            base = 0.35
            if tld_is_suspicious: base += 0.25
            if domain_has_auth_keywords: base += 0.25
            elif domain_has_any_keywords: base += 0.10
            techniques.append({
                "reason": app_reason,
                "technique": "appender",
                "confidence": min(base, 1.0),
            })

        # 4. Distance-2 with name closeness
        if dist == 2:
            name_dist = levenshtein_distance(domain_name, target_name)
            if name_dist <= 2:
                base = 0.20
                if tld_is_suspicious: base += 0.20
                if domain_has_auth_keywords: base += 0.25
                elif domain_has_any_keywords: base += 0.10
                techniques.append({
                    "reason": f"Possible typosquatting: 2 edits from {target}",
                    "technique": "levenshtein_2",
                    "confidence": min(base, 1.0),
                })

        # 5. Repeated/missing character attacks
        rep_reason = _check_repeated_or_missing_chars(domain_name, target_name)
        if rep_reason:
            base = 0.20
            if tld_is_suspicious: base += 0.20
            if domain_has_auth_keywords: base += 0.25
            elif domain_has_any_keywords: base += 0.10
            techniques.append({
                "reason": rep_reason,
                "technique": "char_manipulation",
                "confidence": min(base, 1.0),
            })

        # Pick the best technique for this target
        if techniques:
            best_tech = max(techniques, key=lambda t: t["confidence"])
            if best_tech["confidence"] > best["contextual_confidence"]:
                best = {
                    "detected": True,
                    "brand": target,
                    "reason": best_tech["reason"],
                    "technique": best_tech["technique"],
                    "severity": "high" if best_tech["confidence"] >= 0.5 else "moderate",
                    "contextual_confidence": best_tech["confidence"],
                }

    return best


# ============================================================
# TIER 1: Pure CPU heuristics — instant, no network calls
# ============================================================

def run_heuristics(url: str) -> Dict[str, Any]:
    """
    Pure CPU heuristic analysis. No network calls.
    Runs advanced impersonation detection, punycode check, TLD/keyword synergy.
    Target: <1ms execution time.
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()

    if ':' in domain:
        domain = domain.split(':')[0]

    parts = domain.split('.')
    if len(parts) > 2:
        root_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = domain

    tld = f".{parts[-1]}" if parts else ""
    domain_name_for_context = parts[-2] if len(parts) >= 2 else ""

    # Compute phishing context for impersonation scoring
    has_auth_context = any(kw in domain_name_for_context.lower() for kw in
        ['login', 'signin', 'verify', 'auth', 'secure', 'account',
         'password', 'credential', '2fa', 'mfa', 'otp', 'wallet'])

    # Suspicious keywords in domain
    has_suspicious_keywords = (
        any(kw in root_domain for kw in SUSPICIOUS_KEYWORDS)
        and root_domain not in [f"{t}.com" for t in HIGH_VALUE_TARGETS]
    )

    # Advanced Impersonation Detection with contextual confidence
    has_context_for_imp = has_auth_context or has_suspicious_keywords
    impersonation = detect_impersonation(domain, tld=tld, has_suspicious_keywords=has_context_for_imp)
    typosquatting_detected = impersonation["detected"]
    brand_penalty_reason = impersonation["reason"]
    impersonation_severity = impersonation["severity"]
    impersonation_brand = impersonation["brand"]
    impersonation_technique = impersonation["technique"]
    impersonation_contextual_confidence = impersonation.get("contextual_confidence", 0.0)

    # Synergy Check (TLD + Keywords)
    synergy_detected = False
    synergy_reason = None
    if tld in SUSPICIOUS_TLDS and any(kw in domain for kw in HIGH_RISK_KEYWORDS):
        synergy_detected = True
        synergy_reason = "High-Risk TLD & Keyword Synergy (Phishing Pattern)"

    # Punycode / Homograph detection
    punycode_detected = "xn--" in domain

    return {
        "typosquatting_detected": typosquatting_detected,
        "brand_penalty_reason": brand_penalty_reason,
        "impersonation_severity": impersonation_severity,
        "impersonation_brand": impersonation_brand,
        "impersonation_technique": impersonation_technique,
        "impersonation_contextual_confidence": impersonation_contextual_confidence,
        "impersonation_has_auth_context": has_auth_context,
        "synergy_detected": synergy_detected,
        "synergy_reason": synergy_reason,
        "punycode_detected": punycode_detected,
        "has_suspicious_keywords": has_suspicious_keywords,
        "root_domain": root_domain,
        "domain": domain,
    }

async def fetch_ssl_cert_age(hostname: str) -> Optional[int]:
    """
    Asynchronously fetches SSL certificate 'notBefore' date and computes age in days.
    Uses asyncio.open_connection for a non-blocking TLS handshake.
    """
    try:
        context = ssl.create_default_context()
        # Fully async connection + TLS handshake
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=context, server_hostname=hostname),
            timeout=SSL_CERT_TIMEOUT_S
        )
        
        cert = writer.get_extra_info('peercert')
        writer.close()
        await writer.wait_closed()
        
        if not cert or 'notBefore' not in cert:
            return None
            
        # Format: 'May 15 00:00:00 2024 GMT'
        issued_date_str = cert['notBefore']
        # Parse and ensure UTC
        issued_date = datetime.strptime(issued_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - issued_date).days
        return max(0, age_days)
    except Exception:
        # Fail gracefully: SSL issues are not always malicious
        return None

# ============================================================
# TIER 2: External network lookups — async, non-blocking
# ============================================================

_phishtank_urls = set()
_phishtank_domains = set()
_phishtank_task = None

async def sync_phishtank_feed() -> None:
    """Background task to periodically fetch and update the PhishTank feed."""
    global _phishtank_urls, _phishtank_domains
    while True:
        try:
            logger.info("[PHISHTANK] Starting feed sync...")
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, headers={"User-Agent": "phishtank/vigilantlink"}) as client:
                response = await client.get(PHISHTANK_FEED_URL)
                if response.status_code == 200:
                    data = response.json()
                    new_urls = set()
                    new_domains = set()
                    for entry in data:
                        url = entry.get("url")
                        if url:
                            norm_url = _normalize_gsb_url(url)
                            if norm_url:
                                new_urls.add(norm_url)
                                parsed = urllib.parse.urlparse(norm_url)
                                new_domains.add(parsed.netloc)
                    
                    _phishtank_urls = new_urls
                    _phishtank_domains = new_domains
                    logger.info(f"[PHISHTANK] Synced {len(_phishtank_urls)} URLs and {len(_phishtank_domains)} domains.")
                else:
                    logger.warning(f"[PHISHTANK] Failed to fetch feed, status {response.status_code}")
        except Exception as e:
            logger.error(f"[PHISHTANK] Sync error: {e}")
            
        await asyncio.sleep(PHISHTANK_REFRESH_INTERVAL_S)

def start_phishtank_sync() -> None:
    global _phishtank_task
    if _phishtank_task is None:
        _phishtank_task = asyncio.create_task(sync_phishtank_feed())

def stop_phishtank_sync() -> None:
    global _phishtank_task
    if _phishtank_task:
        _phishtank_task.cancel()
        _phishtank_task = None

def _normalize_gsb_url(target: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
        parsed = urllib.parse.urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


async def check_google_safe_browsing(url: str) -> List[str]:
    """Check a URL against Google Safe Browsing v4 threatMatches."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    normalized = _normalize_gsb_url(url)
    logger.info(f"[GSB] Checking URL: {url} -> Normalized: {normalized} (API Key present: {bool(api_key)})")
    if not api_key or not normalized:
        return []

    payload = {
        "client": {
            "clientId": "vigilantlink",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": GSB_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM", "WINDOWS", "LINUX", "OSX", "CHROME", "IOS", "ANDROID"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized}],
        },
    }

    try:
        timeout = httpx.Timeout(GSB_TIMEOUT_S)
        async with httpx.AsyncClient(timeout=timeout) as client:
            logger.info(f"[GSB] Request payload: {payload}")
            response = await client.post(
                GSB_API_URL,
                params={"key": api_key},
                json=payload,
            )

            logger.info(f"[GSB] API Response status: {response.status_code}")
            if response.status_code == 429:
                logger.warning(f"[GSB] Rate limit hit")
                return []

            if response.status_code != 200:
                logger.error(f"[GSB] API returned {response.status_code}: {response.text}")
                return []

            data = response.json()
            logger.info(f"[GSB] API Response body: {data}")
            matches = data.get("matches", [])
            threats = [match.get("threatType") for match in matches if match.get("threatType") in GSB_THREAT_TYPES]
            results = list(dict.fromkeys([t for t in threats if t]))
            logger.info(f"[GSB] Parsed threat matches: {results}")
            return results

    except httpx.TimeoutException:
        logger.debug(f"[GSB] Request timed out")
    except Exception as e:
        logger.error(f"[GSB] Check failed: {e}")

    return []


async def run_external_scans(domain: str) -> Dict[str, Any]:
    """
    Tier 2: Run RDAP + GSB in parallel.
    'domain' can be a hostname or a full URL.
    """
    parsed = urllib.parse.urlparse(domain)
    if parsed.scheme and parsed.netloc:
        target_domain = parsed.netloc.split(':')[0]
        gsb_url = urllib.parse.urlunparse(parsed)
    else:
        target_domain = domain
        gsb_url = f"http://{domain}"

    parts = target_domain.split('.')
    if len(parts) > 2:
        root_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        root_domain = target_domain

    ssl_timed_out = False
    gsb_timed_out = False
    rdap_timed_out = False
 
    async def _safe_ssl() -> Optional[int]:
        nonlocal ssl_timed_out
        try:
            return await asyncio.wait_for(
                fetch_ssl_cert_age(target_domain), timeout=SSL_CERT_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            ssl_timed_out = True
            logger.warning(f"SSL cert age timeout: {target_domain}")
            return None
        except Exception as e:
            logger.debug(f"SSL cert age failed for {target_domain}: {e}")
            return None

    async def _safe_gsb() -> List[str]:
        nonlocal gsb_timed_out
        try:
            return await asyncio.wait_for(
                check_google_safe_browsing(gsb_url), timeout=GSB_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            gsb_timed_out = True
            return []

    async def _safe_rdap() -> int:
        nonlocal rdap_timed_out
        try:
            return await asyncio.wait_for(
                fetch_domain_age_rdap(root_domain), timeout=RDAP_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            rdap_timed_out = True
            return DEFAULT_DOMAIN_AGE_DAYS

 
    results = await asyncio.gather(
        _safe_ssl(), _safe_gsb(), _safe_rdap()
    )
    cert_age, gsb_results, domain_age = results
 
    norm_url = _normalize_gsb_url(gsb_url)
    pt_url_match = norm_url in _phishtank_urls if norm_url else False
    
    # Domain match: only if NOT a trusted platform (prevents open redirect false positives)
    is_trusted = any(target_domain == d or target_domain.endswith(f".{d}") for d in TRUSTED_PLATFORMS)
    pt_domain_match = (target_domain in _phishtank_domains) and not is_trusted

    gsb_threat_type: Optional[str] = None
    if gsb_results:
        for threat in GSB_THREAT_PRIORITY:
            if threat in gsb_results:
                gsb_threat_type = threat
                break
 
    threat_type: Optional[str] = None
    if gsb_threat_type:
        threat_type = gsb_threat_type
    elif cert_age is not None and cert_age < 7:
        threat_type = "Recently Issued SSL Certificate"
    elif domain_age < NEWLY_REGISTERED_DAYS:
        threat_type = "Newly Registered Domain"
 
    return {
        "ssl_cert_age_days": cert_age,
        "domain_age_days": domain_age,
        "threat_type": threat_type,
        "gsb_threats": gsb_results,
        "gsb_matched": bool(gsb_results),
        "gsb_threat_type": gsb_threat_type,
        "rdap_timed_out": rdap_timed_out,
        "pt_url_match": pt_url_match,
        "pt_domain_match": pt_domain_match,
    }


# Legacy combined function (kept for backward compatibility)
async def scan_url(url: str) -> Dict[str, Any]:
    """Combined scan — runs heuristics + external scans together."""
    heuristics = run_heuristics(url)
    external = await run_external_scans(heuristics["root_domain"])

    # Merge threat_type: heuristic threats take priority
    threat_type = external.get("threat_type")
    if heuristics.get("brand_penalty_reason"):
        threat_type = "Typosquatting Detected (High Value Target)"
    elif heuristics.get("synergy_detected"):
        threat_type = heuristics["synergy_reason"]
    elif heuristics.get("has_suspicious_keywords"):
        threat_type = threat_type or "Suspicious Keywords in Domain"

    return {
        **heuristics,
        **external,
        "threat_type": threat_type,
    }
