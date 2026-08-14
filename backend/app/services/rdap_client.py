"""
RDAP Client: HTTP/JSON-based domain age lookup.

Uses authoritative IANA RDAP bootstrap routing directly,
with fallback to rdap.iana.org and rdap.org.
"""

import datetime
import logging
from typing import Optional
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

# Pre-populated IANA RDAP Bootstrap Endpoints for common TLDs
IANA_BOOTSTRAP_MAP: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/domain/{domain}",
    "net": "https://rdap.verisign.com/net/v1/domain/{domain}",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/{domain}",
    "info": "https://rdap.afilias.net/rdap/domain/{domain}",
    "pro": "https://rdap.afilias.net/rdap/domain/{domain}",
    "mobi": "https://rdap.afilias.net/rdap/domain/{domain}",
    "io": "https://rdap.identitydigital.services/rdap/domain/{domain}",
    "dev": "https://rdap.nic.google/domain/{domain}",
    "app": "https://rdap.nic.google/domain/{domain}",
    "page": "https://rdap.nic.google/domain/{domain}",
    "zip": "https://rdap.nic.google/domain/{domain}",
    "biz": "https://rdap.neustar.biz/rdap/domain/{domain}",
    "co": "https://rdap.nic.co/domain/{domain}",
    "me": "https://rdap.nic.me/domain/{domain}",
    "xyz": "https://rdap.centralnic.com/xyz/domain/{domain}",
    "online": "https://rdap.centralnic.com/online/domain/{domain}",
    "site": "https://rdap.centralnic.com/site/domain/{domain}",
    "store": "https://rdap.centralnic.com/store/domain/{domain}",
    "tech": "https://rdap.centralnic.com/tech/domain/{domain}",
    "shop": "https://rdap.centralnic.com/shop/domain/{domain}",
    "club": "https://rdap.centralnic.com/club/domain/{domain}",
    "us": "https://rdap.nic.us/domain/{domain}",
    "ca": "https://rdap.ca.fury.ca/rdap/domain/{domain}",
    "uk": "https://rdap.nominet.uk/uk/domain/{domain}",
    "co.uk": "https://rdap.nominet.uk/uk/domain/{domain}",
    "in": "https://rdap.registry.in/domain/{domain}",
    "co.in": "https://rdap.registry.in/domain/{domain}",
    "eu": "https://rdap.eurid.eu/domain/{domain}",
    "de": "https://rdap.denic.de/domain/{domain}",
    "nl": "https://rdap.sidn.nl/domain/{domain}",
    "fr": "https://rdap.afnic.fr/rdap/domain/{domain}",
    "ch": "https://rdap.nic.ch/domain/{domain}",
    "se": "https://rdap.iis.se/domain/{domain}",
    "br": "https://rdap.registro.br/domain/{domain}",
    "jp": "https://rdap.jprs.jp/rdap/domain/{domain}",
    "au": "https://rdap.auda.org.au/domain/{domain}",
    "com.au": "https://rdap.auda.org.au/domain/{domain}",
}


def extract_root_domain(url_or_domain: str) -> str:
    """Extract registrable root domain from URL or domain string."""
    cleaned = url_or_domain.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urllib.parse.urlparse(cleaned)
        host = parsed.netloc or parsed.path
    else:
        host = cleaned.split('/')[0]

    host = host.split(':')[0].lower().strip(".")
    parts = host.split('.')
    if len(parts) <= 2:
        return host

    two_part_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "ne.jp", "or.jp",
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
        "com.br", "net.br", "org.br",
        "co.nz", "net.nz", "org.nz",
        "com.sg", "edu.sg",
        "co.za", "org.za",
        "com.tr", "org.tr",
        "co.kr", "ne.kr",
        "com.mx", "org.mx",
        "com.tw", "org.tw",
        "com.hk", "org.hk",
        "com.my", "net.my",
        "com.ph", "gov.ph"
    }
    potential_tld = f"{parts[-2]}.{parts[-1]}"
    if potential_tld in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{potential_tld}"

    return f"{parts[-2]}.{parts[-1]}"


def get_rdap_candidate_urls(root_domain: str) -> list[str]:
    """Build list of candidate RDAP lookup URLs (Authoritative -> IANA -> RDAP.org)."""
    parts = root_domain.split('.')
    tld = parts[-1].lower() if parts else ""
    multi_tld = f"{parts[-2]}.{parts[-1]}".lower() if len(parts) >= 2 else ""

    urls = []
    if multi_tld in IANA_BOOTSTRAP_MAP:
        urls.append(IANA_BOOTSTRAP_MAP[multi_tld].format(domain=root_domain))
    elif tld in IANA_BOOTSTRAP_MAP:
        urls.append(IANA_BOOTSTRAP_MAP[tld].format(domain=root_domain))

    urls.append(f"https://rdap.iana.org/domain/{root_domain}")
    urls.append(f"https://rdap.org/domain/{root_domain}")

    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    return deduped


def _parse_rdap_date_to_days(date_str: str) -> Optional[int]:
    """Parse ISO date string into domain age in days."""
    try:
        clean_date = date_str.replace("Z", "+00:00")
        try:
            reg_date = datetime.datetime.fromisoformat(clean_date)
        except ValueError:
            reg_date = datetime.datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)

        if reg_date.tzinfo is None:
            reg_date = reg_date.replace(tzinfo=datetime.timezone.utc)

        now = datetime.datetime.now(datetime.timezone.utc)
        days = max(0, (now - reg_date).days)
        return days
    except Exception as e:
        logger.debug(f"[RDAP] Failed to parse date '{date_str}': {e}")
        return None


async def fetch_domain_age_rdap(url_or_domain: str) -> Optional[int]:
    """
    Fetch domain registration date via RDAP (HTTP/JSON).

    Returns:
        Age in days (int), or None if registration data genuinely cannot be obtained.
    """
    root_domain = extract_root_domain(url_or_domain)
    logger.debug(f"[RDAP] Lookup started: {root_domain}")

    candidate_urls = get_rdap_candidate_urls(root_domain)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/rdap+json, application/json",
    }

    timeout = httpx.Timeout(2.5, connect=1.5)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in candidate_urls:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue

                data = resp.json()
                if not isinstance(data, dict):
                    continue

                events = data.get("events", [])
                if not isinstance(events, list):
                    events = []

                for event in events:
                    if not isinstance(event, dict):
                        continue
                    action = str(event.get("eventAction", "")).lower()
                    if action in ("registration", "created", "creation", "create"):
                        date_str = event.get("eventDate", "")
                        if date_str and isinstance(date_str, str):
                            reg_days = _parse_rdap_date_to_days(date_str)
                            if reg_days is not None:
                                logger.debug(f"[RDAP] Registration date found: {root_domain}")
                                return reg_days

            except httpx.TimeoutException:
                logger.debug(f"[RDAP] Lookup timeout: {root_domain}")
                continue
            except Exception as e:
                logger.debug(f"[RDAP] Endpoint failed for {root_domain} at {url}: {e}")
                continue

    logger.debug(f"[RDAP] Bootstrap lookup failed: {root_domain}")
    return None

