from fastapi import FastAPI
from pydantic import BaseModel
import whois
import tldextract
from datetime import datetime

app = FastAPI()

class URLRequest(BaseModel):
    url: str

def check_domain_age(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days
    except:
        return None
    return None

def looks_phishy(domain: str):
    suspicious_words = ["login", "secure", "verify", "update", "free", "bonus"]
    for word in suspicious_words:
        if word in domain.lower():
            return True
    return False

@app.post("/scan/url")
def scan_url(request: URLRequest):
    extracted = tldextract.extract(request.url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    age_days = check_domain_age(domain)
    phishy = looks_phishy(domain)

    score = 0
    reasons = []

    if age_days is not None and age_days < 180:
        score += 50
        reasons.append("Domain is less than 6 months old")
    if phishy:
        score += 30
        reasons.append("Domain contains suspicious words")
    
    verdict = "Risky" if score >= 50 else "Safe"

    return {
        "url": request.url,
        "domain": domain,
        "age_days": age_days,
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }


@app.get("/")
def home():
    return {"message": "Phishing Scanner API is running 🚀"}