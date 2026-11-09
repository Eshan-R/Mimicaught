import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract
import whois
from bs4 import BeautifulSoup

# URL Shortening Services' Regex Pattern
SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us",
    re.IGNORECASE
)

REQUEST_TIMEOUT = 5  # seconds

def _get_domain_parts(url: str):
    parsed = urlparse(url if "://" in url else f"http://{url}" )
    ext = tldextract.extract(url)
    return parsed, ext


def having_IP_Address(url: str) -> int:
    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    parsed, _ = _get_domain_parts(url)
    host = parsed.hostname or ""
    return 1 if ip_pattern.match(host) else -1

def URL_Length(url: str) -> int:
    length = len(url)
    if length < 54:
        return -1
    elif length <= 75:
        return 0
    return 1

def Shortining_Service(url: str) -> int:
    return 1 if SHORTENING_SERVICES.search(url) else -1

def having_At_Symbol(url: str) -> int:
    return 1 if "@" in url else -1

def double_slash_redirecting(url: str) -> int:
    last_double_slash = url.rfind("//")
    return 1 if last_double_slash > 7 else -1

def Prefix_Suffix(url: str) -> int:
    _, ext = _get_domain_parts(url)
    return 1 if "-" in ext.domain else -1

def having_Sub_Domain(url: str) -> int:
    _, ext = _get_domain_parts(url)
    subdomain = ext.subdomain
    dot_count = subdomain.count(".") if subdomain else 0
    if dot_count == 0:
        return -1
    elif dot_count == 1:
        return 0
    return 1

def HTTPS_token(url: str) -> int:
    parsed, ext = _get_domain_parts(url)
    domain_text = f"{ext.subdomain}.{ext.domain}".lower()
    return 1 if "https" in domain_text else -1

def port(url: str) -> int:
    parsed, _ = _get_domain_parts(url)
    if parsed.port and parsed.port not in (80, 443):
        return 1
    return -1

def SSLfinal_State(url: str) -> int:
    parsed, _ = _get_domain_parts(url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        return -1
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_valid = (not_after - datetime.now(timezone.utc)).days
                return 1 if days_valid > 365 else 0

    except Exception:
        return 1

def Domain_registeration_length(url: str) -> int:
    _, ext = _get_domain_parts(url)
    domain = f"{ext.domain}.{ext.suffix}"
    try:
        w = whois.whois(domain)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        if expiry is None:
            return 1

        days_left = (expiry - datetime.now(timezone.utc)).days
        return -1 if days_left > 365 else 1

    except Exception:
        return 1

def age_of_domain(url: str) -> int:
    _, ext = _get_domain_parts(url)
    domain = f"{ext.domain}.{ext.suffix}"
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return 1
        age_days = (datetime.now(timezone.utc) - created).days
        return -1 if age_days > 180 else 1
    except Exception:
        return 1


def DNSRecord(url :str) -> int:
    _, ext = _get_domain_parts(url)
    domain = f"{ext.domain}{ext.suffix}"
    try:
        socket.gethostbyname(domain)
        return -1
    except Exception:
        return 1

def Redirect(url: str) -> int:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        num_redirects = len(resp.history)
        return 1 if num_redirects > 2 else 0
    except Exception:
        return 1

def Abnormal_URL(url: str) -> int:
    _, ext = _get_domain_parts(url)
    domain = f"{ext.domain}{ext.suffix}"
    try: 
        w = whois.whois(domain)
        registered_name = str(w.domain_name).lower() if w.domain else ""
        return -1 if domain.lower() in registered_name else 1
    except Exception:
        return 1

def _fetch_html(url: str):
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        return BeautifulSoup(resp.text, "html.parser"), resp.url
    except Exception:
        return None, url
 
def Favicon(url: str, soup=None) -> int:
    if soup is None:
        return 1
    icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    if not icon or not icon.get("href"):
        return -1
    _, ext = _get_domain_parts(url)
    return -1 if ext.domain in icon["href"] else 1
 
def Iframe(url: str, soup=None) -> int:
    if soup is None:
        return 1
    return 1 if soup.find_all("iframe") else -1
 
def Request_URL(url: str, soup=None) -> int:
    if soup is None:
        return 1
    _, ext = _get_domain_parts(url)
    tags = soup.find_all(["img", "script", "video", "audio"])
    if not tags:
        return -1
    external = sum(1 for t in tags if t.get("src") and ext.domain not in t.get("src", ""))
    pct_external = external / len(tags)
    return 1 if pct_external > 0.5 else -1
 
def URL_of_Anchor(url: str, soup=None) -> int:
    if soup is None:
        return 1
    _, ext = _get_domain_parts(url)
    anchors = soup.find_all("a", href=True)
    if not anchors:
        return -1
    external = sum(1 for a in anchors if a["href"].startswith("http") and ext.domain not in a["href"])
    pct_external = external / len(anchors)
    return 1 if pct_external > 0.5 else -1
 
def Links_in_tags(url: str, soup=None) -> int:
    if soup is None:
        return 1
    _, ext = _get_domain_parts(url)
    tags = soup.find_all(["link", "script"])
    if not tags:
        return -1
    external = sum(1 for t in tags if t.get("href") or t.get("src"))
    pct_external = external / max(len(tags), 1)
    return 1 if pct_external > 0.6 else -1

def SFH(url: str, soup=None) -> int:
    if soup is None:
        return 1
    forms = soup.find_all("form")
    for f in forms:
        action = f.get("action", "")
        if action in ("", "about:blank"):
            return 1
        _, ext = _get_domain_parts(url)
        if ext.domain not in action and action.startswith("http"):
            return 0
    return -1

def Submitting_to_email(url: str, soup=None) -> int:
    if soup is None:
        return -1
    forms = soup.find_all("form")
    return 1 if any("mailto:" in f.get("action", "") for f in forms) else -1
 
 
# ---------------------------------------------------------------------------
# TIER 4 - unavailable free data source -> neutral default, documented
# ---------------------------------------------------------------------------
 
def web_traffic(url: str) -> int:
    # TODO (future improvement): integrate the Tranco list (free, downloadable
    # ranking dataset) as a replacement for the discontinued Alexa API.
    return 0
 
 
def Page_Rank(url: str) -> int:
    # TODO (future improvement): integrate Open PageRank's free-tier API.
    return 0
 
 
def Google_Index(url: str) -> int:
    # TODO (future improvement): unreliable to check without a paid Search API
    # (Google blocks scraping of "site:" queries) - defaulting neutral for now.
    return 0
 
 
def Links_pointing_to_page(url: str) -> int:
    # TODO (future improvement): needs a backlink database (Moz/Ahrefs-style),
    # which is paid - defaulting neutral for now.
    return 0
 
 
def Statistical_report(url: str) -> int:
    # TODO (future improvement): cross-check against a blocklist (e.g. PhishTank
    # export, StopBadware) - defaulting neutral for now.
    return 0
 
 
# JS-dependent features - can't be checked from static HTML alone (TIER 4)
def on_mouseover(url: str) -> int:
    return 0  # TODO: needs headless browser (Selenium/Playwright) to detect
 
 
def RightClick(url: str) -> int:
    return 0  # TODO: needs headless browser
 
 
def popUpWidnow(url: str) -> int:
    return 0  # TODO: needs headless browser
  
FEATURE_COLUMNS = [
    "having_IPhaving_IP_Address", "URLURL_Length", "Shortining_Service",
    "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
    "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
    "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor",
    "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
    "Google_Index", "Links_pointing_to_page", "Statistical_report",
]
 
 
def extract_features(url: str) -> dict:
    """Given a raw URL, returns a dict of all 29 features the model expects."""
    soup, _ = _fetch_html(url)
 
    values = {
        "having_IPhaving_IP_Address": having_IP_Address(url),
        "URLURL_Length": URL_Length(url),
        "Shortining_Service": Shortining_Service(url),
        "having_At_Symbol": having_At_Symbol(url),
        "double_slash_redirecting": double_slash_redirecting(url),
        "Prefix_Suffix": Prefix_Suffix(url),
        "having_Sub_Domain": having_Sub_Domain(url),
        "SSLfinal_State": SSLfinal_State(url),
        "Domain_registeration_length": Domain_registeration_length(url),
        "Favicon": Favicon(url, soup),
        "port": port(url),
        "HTTPS_token": HTTPS_token(url),
        "Request_URL": Request_URL(url, soup),
        "URL_of_Anchor": URL_of_Anchor(url, soup),
        "Links_in_tags": Links_in_tags(url, soup),
        "SFH": SFH(url, soup),
        "Submitting_to_email": Submitting_to_email(url, soup),
        "Abnormal_URL": Abnormal_URL(url),
        "Redirect": Redirect(url),
        "on_mouseover": on_mouseover(url),
        "RightClick": RightClick(url),
        "popUpWidnow": popUpWidnow(url),
        "Iframe": Iframe(url, soup),
        "age_of_domain": age_of_domain(url),
        "DNSRecord": DNSRecord(url),
        "web_traffic": web_traffic(url),
        "Page_Rank": Page_Rank(url),
        "Google_Index": Google_Index(url),
        "Links_pointing_to_page": Links_pointing_to_page(url),
        "Statistical_report": Statistical_report(url),
    }
    return values
 
 
if __name__ == "__main__":
    test_url = "https://www.wikipedia.org"
    result = extract_features(test_url)
    for k, v in result.items():
        print(f"{k}: {v}")