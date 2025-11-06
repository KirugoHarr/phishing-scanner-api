from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.utils import (
    extract_domain,
    uses_https,
    is_ip_domain,
    domain_length,
    subdomain_count,
    check_domain_age,
    looks_phishy,
    ssl_expiry_days,
    has_valid_dns_records
)

app = FastAPI(
    title="Phishing Scanner API",
    description="Scans URLs for phishing risk using multiple heuristics",
    version="1.0.0"
)

class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {"message": "Welcome to the Phishing Scanner API!"}


@app.post("/scan/url")
def scan_url(request: URLRequest):
    try:
        # 1. Extract the domain
        domain = extract_domain(request.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 2. Run heuristics
    https_used = uses_https(request.url)
    ip_used = is_ip_domain(domain)
    d_length = domain_length(domain)
    subdomains = subdomain_count(request.url)
    age_days = check_domain_age(domain)
    phishy = looks_phishy(domain)
    ssl_days_left = ssl_expiry_days(domain)
    dns_valid = has_valid_dns_records(domain)

    # ---- Pattern / Obfuscation Checks ----
    at_symbol = "@" in request.url
    suspicious_encoding = any(ch in request.url for ch in ["%00", "%2e", "%2f"])

    # ✅ Adjusted Long Path Logic
    TRUSTED_DOMAINS = ["google.com", "microsoft.com", "amazon.com", "facebook.com", "apple.com"]
    long_path_threshold = 120
    path_len = len("/".join(request.url.split("/")[3:]))  # path + query after domain
    long_path = path_len > long_path_threshold and domain not in TRUSTED_DOMAINS

    # 3. Scoring
    score = 0
    reasons = []

    if not https_used:
        score += 20
        reasons.append("URL does not use HTTPS")

    if ip_used:
        score += 30
        reasons.append("Domain is an IP address instead of a name")

    if d_length > 25:
        score += 20
        reasons.append("Domain name is unusually long")

    if subdomains > 2:
        score += 20
        reasons.append(f"URL has too many subdomains ({subdomains})")

    if age_days is not None and age_days < 180:
        score += 25
        reasons.append(f"Domain is very new (only {age_days} days old)")

    if phishy:
        score += 25
        reasons.append("Domain contains suspicious keywords")

    if ssl_days_left is not None and ssl_days_left < 30:
        score += 10
        reasons.append("SSL certificate expires soon")

    if not dns_valid:
        score += 25
        reasons.append("Domain has no valid DNS records")

    if at_symbol:
        score += 35
        reasons.append("URL contains '@' which can obscure true destination")

    if suspicious_encoding:
        score += 15
        reasons.append("URL uses suspicious or encoded characters")

    if long_path:
        score += 5   # ⚖️ reduced weight for long path
        reasons.append("URL has an unusually long path")

    # 4. Verdict
    verdict = "Risky" if score >= 50 else "Safe"

    # 5. Risk Level & Guidance
    if score < 30:
        risk_level = "Low"
        guidance = "This URL looks generally safe, but stay cautious online."
    elif 30 <= score < 60:
        risk_level = "Medium"
        guidance = "This URL shows some warning signs. Verify the source before proceeding."
    else:
        risk_level = "High"
        guidance = "This URL is highly suspicious. Avoid clicking or sharing it."

    return {
        "url": request.url,
        "domain": domain,
        "https_used": https_used,
        "ip_used": ip_used,
        "domain_length": d_length,
        "subdomains": subdomains,
        "age_days": age_days,
        "ssl_days_left": ssl_days_left,
        "dns_valid": dns_valid,
        "at_symbol": at_symbol,
        "suspicious_encoding": suspicious_encoding,
        "long_path": long_path,
        "score": score,
        "verdict": verdict,
        "risk_level": risk_level,
        "guidance": guidance,
        "reasons": reasons
    }