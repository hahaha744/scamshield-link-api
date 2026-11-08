import contextlib
import ipaddress
import math
import os
import re
import socket
import threading
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

CLOUD_APP_PLATFORMS = {
    "appspot.com", "firebaseapp.com", "web.app", "pages.dev",
    "vercel.app", "netlify.app", "github.io", "glitch.me",
    "workers.dev", "render.com"
}

TRUSTED_BRANDS = {
    "google", "paypal", "apple", "microsoft", "amazon",
    "facebook", "instagram", "netflix", "bankofamerica",
    "chase", "wellsfargo", "binance", "coinbase", "wikipedia",
    "github", "twitter", "linkedin", "youtube", "python", "mozilla"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking",
    "secure", "signin", "credential", "passcode",
    "authenticate", "wallet", "confirm", "phishing",
    "malware", "security", "verification", "authorize",
    "reset-password", "billing", "invoice", "supportdesk"
]

# Thread-Safe In-Memory TTL Cache and Request Coalescer State
MAX_CACHE_ENTRIES = 10000

_gsb_cache = {}          # { url_string: (status_str, expire_monotonic_timestamp) }
_gsb_reserved = set()    # { url_string }
_gsb_cache_lock = threading.Lock()

class InFlightRequest:
    def __init__(self):
        self.event = threading.Event()
        self.result = "unavailable"

_in_flight_requests = {} # { url_string: InFlightRequest_instance }
_in_flight_lock = threading.Lock()

def parse_cache_duration(duration_str) -> float:
    """
    Parses Google API cacheDuration strings like '300s' or '300.5s'.
    Requires string ending in exactly 's' with positive float/int value.
    Rejects malformed strings ('300ss', '300seconds', 'invalid'), zero ('0s'), and negative durations.
    Returns positive float seconds if valid, or None if invalid.
    """
    if not duration_str or not isinstance(duration_str, str):
        return None
    s = duration_str.strip()
    if not s.endswith("s") or s.endswith("ss") or s.endswith("seconds"):
        return None
    val_str = s[:-1]
    if not re.match(r"^\d+(\.\d+)?$", val_str):
        return None
    try:
        val = float(val_str)
        if val > 0.0 and not math.isnan(val) and not math.isinf(val):
            return val
        return None
    except (ValueError, TypeError):
        return None

def reserve_cache_capacity(url: str) -> bool:
    """
    Atomically checks cache capacity and reserves a slot for url if total used (unexpired entries + active reservations) < MAX_CACHE_ENTRIES.
    Purges expired entries first.
    Returns True if reservation was granted or url is already in cache/reserved.
    Returns False if cache is at capacity with unexpired entries.
    """
    now = time.monotonic()
    with _gsb_cache_lock:
        expired_keys = [k for k, v in _gsb_cache.items() if now >= v[1]]
        for k in expired_keys:
            del _gsb_cache[k]

        if url in _gsb_cache or url in _gsb_reserved:
            return True

        total_used = len(_gsb_cache) + len(_gsb_reserved)
        if total_used < MAX_CACHE_ENTRIES:
            _gsb_reserved.add(url)
            return True

        return False

def release_cache_reservation(url: str):
    """Releases capacity reservation if network request fails or cannot be cached."""
    with _gsb_cache_lock:
        _gsb_reserved.discard(url)

def convert_reservation_to_cache(url: str, status: str, duration_sec: float) -> bool:
    """
    Converts active reservation for url into an unexpired cache entry.
    Releases reservation in all cases.
    NEVER evicts unexpired entries.
    Returns True if successfully inserted into cache.
    """
    now = time.monotonic()
    with _gsb_cache_lock:
        _gsb_reserved.discard(url)

        if status not in ("confirmed_threat", "no_match") or not duration_sec or duration_sec <= 0.0:
            return False

        expired_keys = [k for k, v in _gsb_cache.items() if now >= v[1]]
        for k in expired_keys:
            del _gsb_cache[k]

        if len(_gsb_cache) >= MAX_CACHE_ENTRIES and url not in _gsb_cache:
            return False

        expire_time = now + duration_sec
        _gsb_cache[url] = (status, expire_time)
        return True

def get_cached_gsb_status(url: str):
    """
    Returns cached status string if present and unexpired.
    Does NOT extend expiration time on cache hit.
    Purges expired entry if found expired.
    """
    now = time.monotonic()
    with _gsb_cache_lock:
        if url in _gsb_cache:
            status, expire_time = _gsb_cache[url]
            if now < expire_time:
                return status
            else:
                del _gsb_cache[url]
    return None

def clear_gsb_cache_for_testing():
    """Helper function to clear cache, reservations, and in-flight locks during testing."""
    with _gsb_cache_lock:
        _gsb_cache.clear()
        _gsb_reserved.clear()
    with _in_flight_lock:
        _in_flight_requests.clear()

class PinnedHTTPSConnection(HTTPSConnection):
    """Per-connection object that connects directly to _pinned_ip while preserving SNI & Host header."""
    def __init__(self, *args, **kwargs):
        pinned_ip = kwargs.pop('_pinned_ip', None)
        super().__init__(*args, **kwargs)
        if pinned_ip:
            self._pinned_ip = pinned_ip
            self.server_hostname = self.host
            self.host = pinned_ip

    def _new_conn(self):
        pinned_ip = getattr(self, '_pinned_ip', None)
        if not pinned_ip:
            raise RuntimeError("FAIL CLOSED: Connection object missing _pinned_ip attribute! Unpinned DNS lookup blocked.")
        return super()._new_conn()

class PinnedHTTPConnection(HTTPConnection):
    """Per-connection object that connects directly to _pinned_ip while preserving Host header."""
    def __init__(self, *args, **kwargs):
        pinned_ip = kwargs.pop('_pinned_ip', None)
        super().__init__(*args, **kwargs)
        if pinned_ip:
            self._pinned_ip = pinned_ip
            self.host = pinned_ip

    def _new_conn(self):
        pinned_ip = getattr(self, '_pinned_ip', None)
        if not pinned_ip:
            raise RuntimeError("FAIL CLOSED: Connection object missing _pinned_ip attribute! Unpinned DNS lookup blocked.")
        return super()._new_conn()

class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection

class PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection

class PinnedAdapter(HTTPAdapter):
    """Per-request HTTPAdapter configuring pools & connections with validated IP pinning without global socket mutation."""
    def __init__(self, pinned_ip, *args, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _patch_pool(self, pool):
        if pool:
            if isinstance(pool, HTTPSConnectionPool) or getattr(pool, 'scheme', '') == 'https':
                pool.__class__ = PinnedHTTPSConnectionPool
                pool.ConnectionCls = PinnedHTTPSConnection
            else:
                pool.__class__ = PinnedHTTPConnectionPool
                pool.ConnectionCls = PinnedHTTPConnection
            pool.conn_kw['_pinned_ip'] = self._pinned_ip
            pool._pinned_ip = self._pinned_ip
        return pool

    def get_connection(self, url, proxies=None):
        if proxies:
            raise requests.exceptions.ProxyError("Environment or explicit proxies are disabled for SSRF protection")
        pool = super().get_connection(url, proxies=None)
        return self._patch_pool(pool)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if proxies:
            raise requests.exceptions.ProxyError("Environment or explicit proxies are disabled for SSRF protection")
        pool = super().get_connection_with_tls_context(request, verify, proxies=None, cert=cert)
        return self._patch_pool(pool)

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

def check_google_safe_browsing(url: str) -> str:
    """
    Queries Google Safe Browsing API v5 (urls:search GET) if GSB_API_KEY environment variable is set.
    Includes thread-safe TTL caching compliant with Google cacheDuration, atomic capacity reservation,
    and duplicate request coalescing.
    Never hardcodes or logs the API key.
    """
    api_key = os.environ.get("GSB_API_KEY", "").strip()
    if not api_key:
        return "not_configured"

    # 1. Check in-memory TTL cache
    cached = get_cached_gsb_status(url)
    if cached is not None:
        return cached

    # 2. Check and reserve capacity atomically BEFORE making network call
    if not reserve_cache_capacity(url):
        return "unavailable"

    # 3. Request Coalescing with shared InFlightRequest object
    in_flight_obj = None
    is_primary = False

    with _in_flight_lock:
        if url in _in_flight_requests:
            in_flight_obj = _in_flight_requests[url]
        else:
            is_primary = True
            in_flight_obj = InFlightRequest()
            _in_flight_requests[url] = in_flight_obj

    if not is_primary:
        in_flight_obj.event.wait(timeout=3.5)
        return in_flight_obj.result

    # Primary Request Network I/O
    status = "unavailable"
    cached_successfully = False
    try:
        endpoint = "https://safebrowsing.googleapis.com/v5/urls:search"
        params = [
            ("key", api_key),
            ("urls", url)
        ]

        res = requests.get(endpoint, params=params, timeout=3.0)
        if res.status_code == 200:
            try:
                data = res.json()
            except Exception:
                status = "unavailable"
                return status

            if not isinstance(data, dict):
                status = "unavailable"
                return status

            duration_sec = parse_cache_duration(data.get("cacheDuration"))

            if "threats" in data:
                threats = data["threats"]
                if isinstance(threats, list):
                    if len(threats) > 0:
                        candidate_status = "confirmed_threat"
                    else:
                        candidate_status = "no_match"

                    if duration_sec is not None:
                        cached_ok = convert_reservation_to_cache(url, candidate_status, duration_sec)
                        if cached_ok:
                            status = candidate_status
                            cached_successfully = True
                        else:
                            status = "unavailable"
                    else:
                        status = "unavailable"
                else:
                    status = "unavailable"
            else:
                status = "unavailable"
        else:
            status = "unavailable"
    except Exception:
        status = "unavailable"
    finally:
        if not cached_successfully:
            release_cache_reservation(url)
        in_flight_obj.result = status
        in_flight_obj.event.set()
        with _in_flight_lock:
            _in_flight_requests.pop(url, None)

    return status

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

    # 1. Google Safe Browsing Threat Intelligence Lookup
    gsb_status = check_google_safe_browsing(formatted_url)
    if gsb_status == "confirmed_threat":
        return "phishing", 100, {
            "score": 100,
            "verdict": "phishing",
            "signals": ["Confirmed threat match via Google Safe Browsing API"],
            "registered_domain": registered_domain,
            "threat_intel_status": "confirmed_threat"
        }

    score = 0
    signals = []
    has_multiple_risk_signals = False

    # 2. Scheme Validation
    if scheme != "https" and scheme != "http":
        score += 40
        signals.append(f"Unusual scheme '{scheme}'")
    elif scheme == "http":
        score += 15
        signals.append("Insecure HTTP connection (no SSL/TLS)")

    # 3. IP Hostname Check
    if is_ip_address(hostname):
        score += 50
        signals.append(f"Host is a raw IP address ({hostname})")
        has_multiple_risk_signals = True

    # 4. Embedded Credentials Check
    if parsed.username or parsed.password or "@" in raw_input:
        score += 30
        signals.append("URL contains embedded user credentials or '@' symbol")
        has_multiple_risk_signals = True

    # 5. URL Shortener Check
    if registered_domain in KNOWN_SHORTENERS or hostname in KNOWN_SHORTENERS:
        score += 30
        signals.append(f"Recognized URL shortener service ({registered_domain or hostname})")

    # 6. High-Risk TLD Check
    if suffix in HIGH_RISK_TLDS:
        score += 20
        signals.append(f"High-risk top-level domain (.{suffix})")

    # 7. Brand Impersonation & Deceptive Subdomains
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

    # 8. Cloud App Hosting Platform Contextual Risk
    is_cloud_platform = (suffix in CLOUD_APP_PLATFORMS) or (registered_domain in CLOUD_APP_PLATFORMS)
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in decoded_path_query]

    if is_cloud_platform and (matched_keywords or matched_brand):
        score += 35
        signals.append(f"Public cloud app platform ({registered_domain or suffix}) hosting suspicious authentication/security path")
        has_multiple_risk_signals = True

    # 9. Structural Anomalies
    hyphen_count = hostname.count("-")
    if hyphen_count > 2:
        score += 15
        signals.append(f"Excessive hyphens in hostname ({hyphen_count} hyphens)")

    if len(raw_input) > 75:
        score += 15
        signals.append(f"Excessive URL length ({len(raw_input)} characters)")

    # 10. Path & Query Keywords (only if registered domain is NOT an established/trusted brand)
    is_trusted_registered_domain = domain_name in TRUSTED_BRANDS
    if not is_trusted_registered_domain and matched_keywords and not is_cloud_platform:
        score += 15
        signals.append(f"Suspicious path/query keywords found: {', '.join(matched_keywords)}")

    # 11. Encoded / Obfuscated Character Detection
    if "%" in parsed.path or "%" in (parsed.query or ""):
        if re.search(r"%(25|20|40|2f|3c|3e|23)", path_and_query, re.IGNORECASE):
            score += 15
            signals.append("URL contains suspicious percent-encoded obfuscation")

    # 12. Safe Redirect Follower & Anti-SSRF Check
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
        "registered_domain": registered_domain,
        "threat_intel_status": gsb_status
    }

    return verdict, final_score, details

class LinkScanRequest(BaseModel):
    url: str

class LinkScanResponse(BaseModel):
    score: int
    verdict: str
    signals: list = Field(default_factory=list)
    processing_time_ms: float = 0.0
    threat_intel_status: str = "not_configured"

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
            processing_time_ms=elapsed_ms,
            threat_intel_status=details.get("threat_intel_status", "not_configured")
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error processing scan request")

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"status": "ScamShield Link API running"}
