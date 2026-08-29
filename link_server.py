from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import math
import re
import time
from urllib.parse import urlparse

app = FastAPI(title="ScamShield Link API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

link_model = joblib.load("link_model.joblib")
link_model_features = joblib.load("link_model_features.joblib")
LINK_THRESHOLD = 0.25

BRAND_WORDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix",
               "facebook", "bankofamerica", "irs", "instagram", "whatsapp"]
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "confirm",
                     "signin", "banking", "password", "unlock", "suspend"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".live", ".buzz"]

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def longest_char_run(s):
    if not s:
        return 0
    max_run = run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    return max_run

def extract_link_features(url):
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://invalid")
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()
    digits = sum(c.isdigit() for c in url)
    vowels = sum(c in "aeiou" for c in domain)
    return {
        "length_url": len(url), "length_domain": len(domain),
        "nb_dots": url.count("."), "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"), "nb_underscore": url.count("_"),
        "nb_digits": digits, "digit_ratio": digits / max(len(url), 1),
        "nb_subdomains": max(domain.count(".") - 1, 0),
        "has_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]) else 0,
        "is_https": 1 if url.startswith("https") else 0,
        "has_shortener": 1 if any(s in domain for s in SHORTENERS) else 0,
        "has_suspicious_word": 1 if any(w in full for w in SUSPICIOUS_WORDS) else 0,
        "nb_suspicious_words": sum(w in full for w in SUSPICIOUS_WORDS),
        "brand_in_domain": 1 if any(b in domain for b in BRAND_WORDS) else 0,
        "brand_in_path_not_domain": 1 if (
            any(b in path for b in BRAND_WORDS) and not any(b in domain for b in BRAND_WORDS)
        ) else 0,
        "path_length": len(path), "nb_slashes": url.count("/"),
        "has_port": 1 if parsed.port else 0,
        "double_slash_in_path": 1 if "//" in path else 0,
        "domain_entropy": shannon_entropy(domain),
        "vowel_ratio_domain": vowels / max(len(domain), 1),
        "longest_char_run": longest_char_run(domain),
        "has_suspicious_tld": 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
        "nb_com_occurrences": full.count(".com"),
        "nb_percent": url.count("%"),
        "nb_equals": url.count("="),
    }

class LinkScanRequest(BaseModel):
    url: str

@app.post("/scan_link")
def scan_link(request: LinkScanRequest):
    start = time.time()
    feats = extract_link_features(request.url)
    feats_ordered = [feats.get(col, 0) for col in link_model_features]
    prob = float(link_model.predict_proba([feats_ordered])[0][1])
    score = int(round(prob * 100))
    is_suspicious = bool(prob >= LINK_THRESHOLD)
    verdict = "suspicious" if is_suspicious else "safe"
    elapsed_ms = round((time.time() - start) * 1000, 2)
    return {
        "score": score,
        "verdict": verdict,
        "signals": [
            {"label": f"Link model confidence: {score}% phishing likelihood", "flag": is_suspicious}
        ],
        "processing_time_ms": elapsed_ms
    }

@app.get("/")
def root():
    return {"status": "ScamShield Link API running"}