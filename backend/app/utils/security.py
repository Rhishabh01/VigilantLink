import asyncio
import socket
import ipaddress
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

async def is_safe_url(url: str) -> bool:
    """
    Resolves the domain of the URL to an IP address and checks if it belongs
    to private ranges (RFC 1918), loopback (127.0.0.1), or link-local ranges.
    Returns False if the URL is unsafe (internal), True otherwise.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return False

        # Asynchronously resolve domain to IP
        loop = asyncio.get_running_loop()
        try:
            # getaddrinfo returns a list of tuples: (family, type, proto, canonname, sockaddr)
            # sockaddr is a tuple (address, port) for IPv4 or (address, port, flow info, scope id) for IPv6
            infos = await loop.getaddrinfo(domain, None)
        except socket.gaierror:
            # Could not resolve
            return False
            
        if not infos:
            return False
            
        # Get the first resolved IP
        ip_str = infos[0][4][0]
        ip = ipaddress.ip_address(ip_str)

        # Check against restricted ranges
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            logger.warning(f"SSRF Attempt detected: {url} resolves to internal IP {ip_str}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Error checking URL safety for {url}: {e}")
        return False
