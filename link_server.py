import ipaddress
import math
import os
import re
import socket
import time
import urllib.parse
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
import tldextract
import joblib

app = FastAPI(title="ScamShield Link API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Preserve model files on disk; attempt safe loading if present
try:
    link_model = joblib.load("link_model.joblib")
    link_model_features = joblib.load("link_model_features.joblib")
    HAS_ML_MODEL = True
except Exception:
    link_model = None
    link_model_features = None
    HAS_ML_MODEL = False

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "goo.gl", "tiny.cc", "shorturl.at"
}

HIGH_RISK_TLDS = {
    "xyz", "top", "work", "gq", "tk", "ml", "ga", "cf",
    "zip", "mov", "click", "country", "stream", "download",
    "racing", "kim", "fit"
}

TRUSTED_BRANDS = {
    "google", "paypal", "apple", "microsoft", "amazon",
    "facebook", "instagram", "netflix", "bankofamerica",
    "chase", "wellsfargo", "binance", "coinbase", "wikipedia",
    "github", "twitter", "linkedin", "youtube"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking",
    "secure", "signin", "credential", "passcode",
    "authenticate", "wallet", "confirm"
]

class PinnedHTTPSConnection(HTTPSConnection):
    """Per-connection object that connects directly to _pinned_ip while preserving SNI & Host header."""
    def _new_conn(self):
        pinned_ip = getattr(self, '_pinned_ip', None)
        if not pinned_ip:
            raise RuntimeError("FAIL CLOSED: Connection object missing _pinned_ip attribute! Unpinned DNS lookup blocked.")
        saved_host = self.host
        self.host = pinned_ip
        try:
            conn = super()._new_conn()
        finally:
            self.host = saved_host
        return conn

class PinnedHTTPConnection(HTTPConnection):
    """Per-connection object that connects directly to _pinned_ip while preserving Host header."""
    def _new_conn(self):
        pinned_ip = getattr(self, '_pinned_ip', None)
        if not pinned_ip:
            raise RuntimeError("FAIL CLOSED: Connection object missing _pinned_ip attribute! Unpinned DNS lookup blocked.")
        saved_host = self.host
        self.host = pinned_ip
        try:
            conn = super()._new_conn()
        finally:
            self.host = saved_host
        return conn

class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection

    def _new_conn(self):
        conn = super()._new_conn()
        conn._pinned_ip = getattr(self, '_pinned_ip', None)
        return conn

class PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection

    def _new_conn(self):
        conn = super()._new_conn()
        conn._pinned_ip = getattr(self, '_pinned_ip', None)
        return conn

class PinnedAdapter(HTTPAdapter):
    """Per-request HTTPAdapter configuring pools & connections with validated IP pinning without global socket mutation."""
    def __init__(self, pinned_ip, *args, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def get_connection(self, url, proxies=None):
        if proxies:
            raise requests.exceptions.ProxyError("Environment or explicit proxies are disabled for SSRF protection")
        pool = super().get_connection(url, proxies=None)
        if url.startswith('https://'):
            pool.__class__ = PinnedHTTPSConnectionPool
            pool.ConnectionCls = PinnedHTTPSConnection
        else:
            pool.__class__ = PinnedHTTPConnectionPool
            pool.ConnectionCls = PinnedHTTPConnection
        pool._pinned_ip = self._pinned_ip
        return pool

def is_ip_address(host_str: str) -> bool:
    if not host_str:
        return False
    clean_host = host_str.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def is_private_or_reserved_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified
        )
    except ValueError:
        return True

def resolve_hostname_safely(hostname: str):
    if not hostname:
        return False, "Empty hostname"

    clean_host = hostname.strip("[]")

    if is_ip_address(clean_host):
        if is_private_or_reserved_ip(clean_host):
            return False, "IP is private/reserved"
        return True, [clean_host]

    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        ips = list(set([info[4][0] for info in addr_info if info[4]]))
        if not ips:
            return False, "No IP addresses resolved"
        for ip in ips:
            if is_private_or_reserved_ip(ip):
                return False, f"Resolved IP for {hostname} is private/reserved"
        return True, ips
    except socket.gaierror:
        return False, f"DNS resolution failed for {hostname}"
    except Exception:
        return False, f"Hostname verification error for {hostname}"

def resolve_redirects_safely(initial_url: str, max_redirects=3, timeout=3.0):
    current_url = initial_url
    redirect_count = 0

    for _ in range(max_redirects):
        try:
            parsed = urllib.parse.urlparse(current_url)
            hostname = parsed.hostname
            if not hostname:
                break

            is_safe_host, ips_or_err = resolve_hostname_safely(hostname)
            if not is_safe_host:
                return current_url, redirect_count, True

            pinned_ip = ips_or_err[0]
            session = requests.Session()
            session.trust_env = False  # Disable environment proxy hijacking
            session.mount("https://", PinnedAdapter(pinned_ip))
            session.mount("http://", PinnedAdapter(pinned_ip))

            response = None
            try:
                response = session.head(
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                    headers={"User-Agent": "FraudFenderScanner/1.0"}
                )
                if response.status_code == 405:
                    response = session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=timeout,
                        stream=True,
                        headers={"User-Agent": "FraudFenderScanner/1.0"}
                    )
            except requests.RequestException:
                break
            finally:
                session.close()

            if response is not None and response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break
                next_url = urllib.parse.urljoin(current_url, location)
                if next_url == current_url:
                    break
                current_url = next_url
                redirect_count += 1
            else:
                break
        except Exception:
            break

    return current_url, redirect_count, False

def evaluate_url(url_string: str):
    raw_input = url_string.strip()
    if not raw_input:
        raise ValueError("Empty URL string")

    formatted_url = raw_input
    if not re.match(r"^https?://", formatted_url, re.IGNORECASE):
        formatted_url = "http://" + formatted_url

    parsed = urllib.parse.urlparse(formatted_url)
    hostname = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    path_and_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
    decoded_path_query = urllib.parse.unquote(path_and_query)

    extracted = tldextract.extract(formatted_url)
    reg_dom = f"{extracted.domain}.{extracted.suffix}".lower() if (extracted.domain and extracted.suffix) else hostname
    registered_domain = reg_dom
    domain_name = extracted.domain.lower() if extracted.domain else ""
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""

    score = 0
    signals = []
    has_multiple_risk_signals = False

    # 1. Scheme Validation
    if scheme != "https" and scheme != "http":
        score += 40
        signals.append(f"Unusual scheme '{scheme}'")
    elif scheme == "http":
        score += 15
        signals.append("Insecure HTTP connection (no SSL/TLS)")

    # 2. IP Hostname Check
    if is_ip_address(hostname):
        score += 50
        signals.append(f"Host is a raw IP address ({hostname})")
        has_multiple_risk_signals = True

    # 3. Embedded Credentials Check
    if parsed.username or parsed.password or "@" in raw_input:
        score += 30
        signals.append("URL contains embedded user credentials or '@' symbol")
        has_multiple_risk_signals = True

    # 4. URL Shortener Check
    if registered_domain in KNOWN_SHORTENERS or hostname in KNOWN_SHORTENERS:
        score += 30
        signals.append(f"Recognized URL shortener service ({registered_domain or hostname})")

    # 5. High-Risk TLD Check
    if suffix in HIGH_RISK_TLDS:
        score += 20
        signals.append(f"High-risk top-level domain (.{suffix})")

    # 6. Brand Impersonation & Deceptive Subdomains
    matched_brand = None
    for brand in TRUSTED_BRANDS:
        if brand in subdomain or brand in decoded_path_query:
            if domain_name != brand:
                matched_brand = brand
                break

    if matched_brand:
        score += 50
        signals.append(f"Potential brand impersonation: '{matched_brand}' referenced outside official domain '{registered_domain}'")
        has_multiple_risk_signals = True

    # 7. Structural Anomalies
    hyphen_count = hostname.count("-")
    if hyphen_count > 2:
        score += 15
        signals.append(f"Excessive hyphens in hostname ({hyphen_count} hyphens)")

    if len(raw_input) > 75:
        score += 15
        signals.append(f"Excessive URL length ({len(raw_input)} characters)")

    # 8. Path & Query Keywords
    is_trusted_registered_domain = domain_name in TRUSTED_BRANDS
    if not is_trusted_registered_domain:
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in decoded_path_query]
        if matched_keywords:
            score += 15
            signals.append(f"Suspicious path/query keywords found: {', '.join(matched_keywords)}")

    # 9. Encoded / Obfuscated Character Detection
    if "%" in parsed.path or "%" in (parsed.query or ""):
        if re.search(r"%(25|20|40|2f|3c|3e|23)", path_and_query, re.IGNORECASE):
            score += 15
            signals.append("URL contains suspicious percent-encoded obfuscation")

    # 10. Safe Redirect Follower & Anti-SSRF Check
    final_url, redirect_count, ssrf_flag = resolve_redirects_safely(formatted_url)
    if ssrf_flag:
        score += 40
        signals.append("Redirect chain attempted to access private or reserved IP space (SSRF blocked)")
        has_multiple_risk_signals = True
    elif redirect_count > 0:
        final_extracted = tldextract.extract(final_url)
        final_reg_domain = f"{final_extracted.domain}.{final_extracted.suffix}".lower() if (final_extracted.domain and final_extracted.suffix) else ""
        if final_reg_domain and final_reg_domain != registered_domain:
            score += 25
            signals.append(f"URL redirects across domains from '{registered_domain}' to '{final_reg_domain}'")

    final_score = min(100, max(0, score))

    if final_score >= 65 and len(signals) == 1 and not has_multiple_risk_signals:
        verdict = "suspicious"
    elif final_score >= 65:
        verdict = "phishing"
    elif final_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    details = {
        "score": final_score,
        "verdict": verdict,
        "signals": signals if signals else ["No major risk heuristics triggered."],
        "registered_domain": registered_domain
    }

    return verdict, final_score, details

class LinkScanRequest(BaseModel):
    url: str

class LinkScanResponse(BaseModel):
    score: int
    verdict: str
    signals: list = Field(default_factory=list)
    processing_time_ms: float = 0.0

@app.post("/scan_link", response_model=LinkScanResponse)
def scan_link(request_data: LinkScanRequest):
    start = time.time()
    url_text = request_data.url.strip() if request_data.url else ""
    if not url_text:
        raise HTTPException(status_code=400, detail="Missing or empty 'url' field")

    try:
        verdict, score, details = evaluate_url(url_text)
        elapsed_ms = round((time.time() - start) * 1000, 2)

        formatted_signals = [
            {"label": sig, "flag": True} for sig in details.get("signals", [])
        ]

        return LinkScanResponse(
            score=int(score),
            verdict=verdict,
            signals=formatted_signals,
            processing_time_ms=elapsed_ms
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error processing scan request")

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"status": "ScamShield Link API running"}
