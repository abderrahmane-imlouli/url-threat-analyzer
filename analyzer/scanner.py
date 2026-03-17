import os
import re
import time
import base64
import socket
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime, timezone

# ===========================
# CONFIGURATION
# ===========================

# Keys loaded from environment variables — never hardcode them!
VT_API_KEY      = os.environ.get("VT_API_KEY", "")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")

URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
VT_SUBMIT      = "https://www.virustotal.com/api/v3/urls"
VT_RESULT      = "https://www.virustotal.com/api/v3/urls/{url_id}"

# ===========================
# STATIC ANALYSIS
# ===========================

def static_analysis(url):
    results = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        results.append({"type": "error", "message": "URL does not use HTTPS"})

    ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(ip_regex, parsed.netloc):
        results.append({"type": "warning", "message": "URL uses an IP address instead of a domain"})

    suspicious_keywords = ['login', 'verify', 'update', 'free', 'bonus', 'bank', 'paypal', 'secure', 'account', 'confirm']
    found_keywords = [w for w in suspicious_keywords if w in url.lower()]
    if found_keywords:
        results.append({"type": "warning", "message": f"Contains suspicious keywords: {', '.join(found_keywords)}"})

    if len(url) > 100:
        results.append({"type": "warning", "message": f"URL is unusually long ({len(url)} characters)"})

    if len(parsed.netloc.split('.')) > 4:
        results.append({"type": "warning", "message": "URL has many subdomains – possible spoofing"})

    if '%' in url:
        results.append({"type": "warning", "message": "URL contains percent-encoded characters"})

    if not results:
        results.append({"type": "safe", "message": "No obvious problems found in static analysis"})

    return results

# ===========================
# WHOIS ANALYSIS
# ===========================

def check_whois(url):
    results = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith("www."):
            domain = domain[4:]
        domain = domain.split(":")[0]

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        registrar = w.registrar or "Unknown"

        # Fix: handle both timezone-aware and timezone-naive datetimes
        age_warning = None
        if creation_date and isinstance(creation_date, datetime):
            now = datetime.now(timezone.utc) if creation_date.tzinfo is not None else datetime.now()
            age_days = (now - creation_date).days
            if age_days < 30:
                age_warning = f"Domain is only {age_days} days old – HIGH RISK"
            elif age_days < 180:
                age_warning = f"Domain is only {age_days} days old – relatively new"

        results.append({
            "status": "success",
            "domain": domain,
            "registrar": registrar,
            "creation_date": str(creation_date.date()) if creation_date and hasattr(creation_date, 'date') else str(creation_date or "N/A"),
            "expiration_date": str(expiration_date.date()) if expiration_date and hasattr(expiration_date, 'date') else str(expiration_date or "N/A"),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "country": w.country or "N/A",
            "age_warning": age_warning,
        })

    except Exception as e:
        results.append({"status": "error", "message": f"WHOIS lookup failed: {str(e)}"})

    return results

# ===========================
# DNS / IP RESOLUTION
# ===========================

def resolve_dns(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        ip = socket.gethostbyname(domain)
        return {"status": "success", "domain": domain, "ip": ip}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ===========================
# VIRUSTOTAL ANALYSIS
# ===========================

def check_virustotal(url):
    if not VT_API_KEY:
        return {"status": "error", "message": "VT_API_KEY not set in environment variables"}
    headers = {"x-apikey": VT_API_KEY}
    try:
        submit = requests.post(VT_SUBMIT, data={"url": url}, headers=headers, timeout=15)
        if submit.status_code != 200:
            return {"status": "error", "message": f"Failed to submit URL (HTTP {submit.status_code})"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        time.sleep(5)

        result = requests.get(VT_RESULT.format(url_id=url_id), headers=headers, timeout=15).json()
        stats = result["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        if malicious >= 5:
            threat_level = "high"
        elif malicious >= 1 or suspicious >= 3:
            threat_level = "medium"
        else:
            threat_level = "low"

        return {
            "status": "success",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get('harmless', 0),
            "undetected": stats.get('undetected', 0),
            "threat_level": threat_level,
            "vt_link": f"https://www.virustotal.com/gui/url/{url_id}"
        }
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

# ===========================
# URLSCAN.IO ANALYSIS
# ===========================

def check_urlscan(url):
    if not URLSCAN_API_KEY:
        return {"status": "error", "message": "URLSCAN_API_KEY not set in environment variables"}
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    try:
        submit_resp = requests.post(
            URLSCAN_SUBMIT,
            json={"url": url, "visibility": "public"},
            headers=headers,
            timeout=15
        )
        if submit_resp.status_code == 400:
            return {"status": "error", "message": "Bad request – URL may be invalid"}
        if submit_resp.status_code == 429:
            return {"status": "error", "message": "Rate limit exceeded on urlscan.io"}
        if submit_resp.status_code != 200:
            return {"status": "error", "message": f"Submit failed (HTTP {submit_resp.status_code})"}

        uuid = submit_resp.json().get("uuid")
        if not uuid:
            return {"status": "error", "message": "No UUID returned from urlscan.io"}

        # Poll every 5s up to 60s
        scan_data = None
        for _ in range(12):
            time.sleep(5)
            r = requests.get(URLSCAN_RESULT.format(uuid=uuid), timeout=15)
            if r.status_code == 200:
                scan_data = r.json()
                break
            elif r.status_code == 404:
                continue
            else:
                return {"status": "error", "message": f"Unexpected status {r.status_code} while polling"}

        if not scan_data:
            return {"status": "error", "message": "urlscan.io scan timed out after 60 seconds"}

        overall = scan_data.get("verdicts", {}).get("overall", {})
        page    = scan_data.get("page", {})
        stats   = scan_data.get("stats", {})

        return {
            "status": "success",
            "report_url": f"https://urlscan.io/result/{uuid}/",
            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "malicious": overall.get("malicious", False),
            "score": overall.get("score", 0),
            "categories": overall.get("categories", []),
            "final_url": page.get("url", url),
            "server": page.get("server", "N/A"),
            "ip": page.get("ip", "N/A"),
            "country": page.get("country", "N/A"),
            "total_requests": stats.get("requests", {}).get("total", 0),
            "uuid": uuid
        }
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "Request timed out"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

# ===========================
# FULL SCAN
# ===========================

def full_scan(url):
    return {
        "url": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "static": static_analysis(url),
        "whois": check_whois(url),
        "dns": resolve_dns(url),
        "virustotal": check_virustotal(url),
        "urlscan": check_urlscan(url),
    }
