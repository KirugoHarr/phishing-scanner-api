import ipaddress
import socket
import ssl
from datetime import datetime
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse, unquote

import tldextract
import whois
import logging
import dns.resolver

logger = logging.getLogger("phish-scanner.utils")

# ---------------------------------------------------
# Basic URL and Domain Processing
# ---------------------------------------------------
def extract_domain(url: str) -> str:
    """Extract the main domain from a URL."""
    extracted = tldextract.extract(url)
    if not extracted.domain or not extracted.suffix:
        raise ValueError("Could not extract domain from URL")
    return f"{extracted.domain}.{extracted.suffix}"


def uses_https(url: str) -> bool:
    """Return True if the URL uses HTTPS."""
    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False


def is_ip_domain(domain: str) -> bool:
    """Return True if the domain is an IP address."""
    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False


def domain_length(domain: str) -> int:
    """Return the length (characters) of the domain."""
    return len(domain or "")


def subdomain_count(url: str) -> int:
    """
    Return the number of subdomain labels.
    e.g. a.b.c.example.com -> 3
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return max(0, len(host.split(".")) - 2)

# ---------------------------------------------------
# Heuristic Checks
# ---------------------------------------------------
@lru_cache(maxsize=512)
def check_domain_age(domain: str) -> Optional[int]:
    """Return the domain age in days (None if unavailable)."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.fromisoformat(creation_date)
                except Exception:
                    logger.debug("Could not parse creation_date: %s", creation_date)
                    return None
            return (datetime.now() - creation_date).days
    except Exception as e:
        logger.debug("Whois lookup failed for %s: %s", domain, e)
    return None


def looks_phishy(domain: str) -> bool:
    """Check if the domain contains common phishing keywords."""
    suspicious_words = [
        "login", "secure", "verify", "update",
        "free", "bonus", "account", "bank"
    ]
    lower = domain.lower()
    return any(w in lower for w in suspicious_words)


def ssl_expiry_days(domain: str, timeout: float = 5.0) -> Optional[int]:
    """Return days until SSL certificate expiry."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert.get("notAfter")
                if notAfter:
                    try:
                        expiry = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    except Exception:
                        expiry = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y")
                    return (expiry - datetime.utcnow()).days
    except Exception as e:
        logger.debug("SSL check failed for %s: %s", domain, e)
    return None

# ---------------------------------------------------
# DNS Validation
# ---------------------------------------------------
def has_valid_dns_records(domain: str) -> bool:
    """Check if domain has at least one valid DNS record (A, MX, or NS)."""
    for record_type in ["A", "MX", "NS"]:
        try:
            dns.resolver.resolve(domain, record_type)
            return True
        except Exception:
            continue
    return False

# ---------------------------------------------------
# URL Pattern & Obfuscation Checks
# ---------------------------------------------------
def has_at_symbol(url: str) -> bool:
    """Return True if '@' appears in the URL (often used to mislead users)."""
    parsed = urlparse(url)
    return '@' in (parsed.netloc + parsed.path)


def has_suspicious_encoding(url: str) -> bool:
    """Return True if there are many encoded characters like %20, %2E, etc."""
    decoded = unquote(url)
    encoded_chars = url.count('%')
    return encoded_chars > 5  # threshold for suspicious encoding


def long_url_path(url: str, max_len: int = 60) -> bool:
    """Return True if the path+query part is unusually long."""
    parsed = urlparse(url)
    path_query = (parsed.path or "") + (parsed.query or "")
    return len(path_query) > max_len


