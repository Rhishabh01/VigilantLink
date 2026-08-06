"""
SSRF Protection: Reusable URL validation utility.

Validates user-supplied URLs before any outbound fetch to prevent
Server-Side Request Forgery (SSRF) attacks.

Blocked ranges:
  - localhost / 127.0.0.0/8
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 169.254.0.0/16 (link-local)
  - IPv6 loopback (::1) and private ranges (fc00::/7, fe80::/10)
  - 0.0.0.0/8 (unspecified)

DNS rebinding mitigation:
  - Resolves the hostname and checks the resulting IP BEFORE allowing the fetch.
  - Callers can pass the pre-resolved IP to their HTTP client to pin the connection.

Redirect safety:
  - Provides a validator callback compatible with httpx event hooks to re-check
    destination IPs on every redirect hop.
"""

import ipaddress
import logging
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private / reserved IPv4 networks
_BLOCKED_IPV4_NETWORKS = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),       # Documentation
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),      # Benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),    # Documentation
    ipaddress.IPv4Network("203.0.113.0/24"),     # Documentation
    ipaddress.IPv4Network("224.0.0.0/4"),        # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),        # Reserved
    ipaddress.IPv4Network("255.255.255.255/32"), # Broadcast
]

# Private / reserved IPv6 networks
_BLOCKED_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::1/128"),            # Loopback
    ipaddress.IPv6Network("::/128"),             # Unspecified
    ipaddress.IPv6Network("::ffff:0:0/96"),      # IPv4-mapped (re-check as v4)
    ipaddress.IPv6Network("fc00::/7"),           # Unique local
    ipaddress.IPv6Network("fe80::/10"),          # Link-local
    ipaddress.IPv6Network("ff00::/8"),           # Multicast
]


def is_ip_blocked(ip_str: str) -> bool:
    """Check whether an IP address falls within any blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        # Unparseable → block by default
        return True

    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _BLOCKED_IPV4_NETWORKS)

    if isinstance(addr, ipaddress.IPv6Address):
        # Check native IPv6 blocks
        if any(addr in net for net in _BLOCKED_IPV6_NETWORKS):
            return True
        # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — extract and re-check
        if addr.ipv4_mapped:
            return any(addr.ipv4_mapped in net for net in _BLOCKED_IPV4_NETWORKS)
        return False

    return True  # Unknown type → block


def validate_url_scheme(url: str) -> bool:
    """Only allow http/https schemes."""
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https")


def resolve_and_validate(url: str) -> Tuple[bool, Optional[str], str]:
    """
    Resolve hostname and validate the resulting IP is not private/reserved.

    Returns:
        (is_safe, resolved_ip, reason)
        - is_safe: True if the URL is safe to fetch
        - resolved_ip: The first resolved IP (for connection pinning), or None
        - reason: Human-readable explanation if blocked
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, None, f"Blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, None, "No hostname in URL"

    # Block raw IP addresses pointing to private ranges
    try:
        addr = ipaddress.ip_address(hostname)
        if is_ip_blocked(str(addr)):
            return False, None, f"Blocked IP: {hostname} is in a private/reserved range"
        return True, str(addr), "ok"
    except ValueError:
        pass  # Not a raw IP — resolve via DNS

    # DNS resolution
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        # DNS failure is not an SSRF issue — let the caller handle connectivity
        return True, None, "DNS resolution failed (not blocked)"

    if not results:
        return True, None, "No DNS results (not blocked)"

    # Check ALL resolved IPs — block if ANY resolve to a private range
    for family, _, _, _, sockaddr in results:
        ip_str = sockaddr[0]
        if is_ip_blocked(ip_str):
            logger.warning(
                f"[SSRF] Blocked request to {hostname}: resolved to private IP {ip_str}"
            )
            return False, None, f"Blocked: {hostname} resolves to private IP {ip_str}"

    # Return the first resolved IP for connection pinning
    first_ip = results[0][4][0]
    return True, first_ip, "ok"


def validate_redirect_target(url: str) -> bool:
    """
    Validate a redirect destination URL.
    Used as a callback during redirect-following to prevent SSRF via redirect.
    
    Returns True if the redirect target is safe to follow.
    """
    is_safe, _, reason = resolve_and_validate(url)
    if not is_safe:
        logger.warning(f"[SSRF] Blocked redirect to {url[:80]}: {reason}")
    return is_safe
