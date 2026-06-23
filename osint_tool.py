# ============================================================
#  PHANTOM-EYE  —  OSINT Reconnaissance Automation Tool
#  Author  : M Ammar Ansari
#  Company : Digital Forensics
#  Version : 1.0
# ============================================================

import socket
import threading
import datetime
import requests
import json
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox

# ── Safe imports (graceful fallback if library missing) ──────
try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False


# ════════════════════════════════════════════════════════════
#  COLOUR PALETTE  (same SOC dark theme)
# ════════════════════════════════════════════════════════════
BG_DEEP  = "#080c10"
BG_PANEL = "#0d1117"
BG_CARD  = "#161b22"
BORDER   = "#21262d"
CYAN     = "#00d4ff"
GREEN    = "#39d353"
AMBER    = "#ff8c00"
RED      = "#ff3040"
PURPLE   = "#a78bfa"
GRAY     = "#8b949e"
WHITE    = "#e6edf3"
DIM      = "#c9d1d9"
PINK     = "#ff79c6"


# ════════════════════════════════════════════════════════════
#  STEP 1 — WHOIS MODULE
#  Retrieves domain registration information
# ════════════════════════════════════════════════════════════
def run_whois(domain):
    """
    WHOIS is a public database that stores domain registration information.
    It works like an identity record for a domain, showing registrar,
    organization, dates, name servers, and public contact details.
    """
    results = {}
    if not WHOIS_OK:
        return {"error": "python-whois not installed. Run: pip install python-whois"}
    try:
        w = whois_lib.whois(domain)
        results["registrar"]      = str(w.registrar or "N/A")
        results["org"]            = str(w.org or "N/A")
        results["country"]        = str(w.country or "N/A")
        results["creation_date"]  = str(w.creation_date[0]
                                        if isinstance(w.creation_date, list)
                                        else w.creation_date or "N/A")
        results["expiry_date"]    = str(w.expiration_date[0]
                                        if isinstance(w.expiration_date, list)
                                        else w.expiration_date or "N/A")
        results["name_servers"]   = (w.name_servers or [])
        results["emails"]         = list(set(w.emails or []))
        results["status"]         = str(w.status[0]
                                        if isinstance(w.status, list)
                                        else w.status or "N/A")
    except Exception as e:
        results["error"] = str(e)
    return results


# ════════════════════════════════════════════════════════════
#  STEP 2 — DNS RECORDS MODULE
#  Retrieves DNS records for the target domain
# ════════════════════════════════════════════════════════════
def run_dns(domain):
    """
    DNS stands for Domain Name System.
    It maps a domain name to IP addresses and other service records.

    Record types:
    A     → IPv4 address of the domain
    AAAA  → IPv6 address of the domain
    MX    → mail servers used by the domain
    NS    → authoritative name servers
    TXT   → SPF, DKIM, DMARC, and verification records
    CNAME → alias record linking one hostname to another
    """
    results = {}
    if not DNS_OK:
        # Fallback: socket se sirf A record
        try:
            ip = socket.gethostbyname(domain)
            results["A"] = [ip]
        except Exception as e:
            results["error"] = str(e)
        return results

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            if rtype == "MX":
                results[rtype] = [f"{r.preference} {r.exchange}" for r in answers]
            elif rtype == "TXT":
                results[rtype] = [r.to_text().strip('"') for r in answers]
            else:
                results[rtype] = [r.to_text() for r in answers]
        except Exception:
            results[rtype] = []
    return results


# ════════════════════════════════════════════════════════════
#  STEP 3 — SUBDOMAIN ENUMERATION
#  Finds public subdomains using Certificate Transparency logs
# ════════════════════════════════════════════════════════════
def run_subdomains(domain):
    """
    Finds public subdomains using multiple safe OSINT methods.

    Primary source:
    - crt.sh Certificate Transparency logs

    Fallback sources:
    - CertSpotter public CT API
    - HackerTarget hostsearch API
    - Small DNS resolution check for common subdomain names

    This prevents the tool from failing completely when crt.sh returns
    HTTP 502, HTTP 429, timeout, or invalid JSON.
    """
    subdomains = set()
    errors = []

    def clean_subdomain(name):
        """Normalize and validate a discovered subdomain."""
        name = name.strip().lower().replace("*.", "")
        name = name.rstrip(".")
        if name == domain or name.endswith(f".{domain}"):
            return name
        return None

    # ── Source 1: crt.sh ──────────────────────────────────
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        if resp.status_code == 200:
            try:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for raw_name in name_value.split("\n"):
                        sub = clean_subdomain(raw_name)
                        if sub:
                            subdomains.add(sub)
            except Exception:
                errors.append("crt.sh returned invalid JSON")
        else:
            errors.append(f"crt.sh HTTP {resp.status_code}")

    except requests.exceptions.Timeout:
        errors.append("crt.sh timeout")
    except requests.exceptions.RequestException as e:
        errors.append(f"crt.sh network error: {e}")
    except Exception as e:
        errors.append(f"crt.sh unexpected error: {e}")

    # ── Source 2: CertSpotter public API ───────────────────
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        resp = requests.get(
            url,
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        if resp.status_code == 200:
            try:
                data = resp.json()
                for item in data:
                    for raw_name in item.get("dns_names", []):
                        sub = clean_subdomain(raw_name)
                        if sub:
                            subdomains.add(sub)
            except Exception:
                errors.append("CertSpotter returned invalid JSON")
        else:
            errors.append(f"CertSpotter HTTP {resp.status_code}")

    except requests.exceptions.Timeout:
        errors.append("CertSpotter timeout")
    except requests.exceptions.RequestException as e:
        errors.append(f"CertSpotter network error: {e}")
    except Exception as e:
        errors.append(f"CertSpotter unexpected error: {e}")

    # ── Source 3: HackerTarget hostsearch ──────────────────
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(
            url,
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                # Format is usually: sub.example.com,93.184.216.34
                raw_name = line.split(",")[0].strip()
                sub = clean_subdomain(raw_name)
                if sub:
                    subdomains.add(sub)
        else:
            errors.append(f"HackerTarget HTTP {resp.status_code} or API error")

    except requests.exceptions.Timeout:
        errors.append("HackerTarget timeout")
    except requests.exceptions.RequestException as e:
        errors.append(f"HackerTarget network error: {e}")
    except Exception as e:
        errors.append(f"HackerTarget unexpected error: {e}")

    # ── Source 4: Small DNS fallback wordlist ──────────────
    # This is not aggressive scanning. It only checks a small set of common names.
    common_names = [
        "www", "mail", "webmail", "ftp", "smtp", "pop", "imap",
        "ns1", "ns2", "dns", "portal", "admin", "cpanel", "blog",
        "dev", "test", "staging", "api", "app", "cdn", "shop", "store",
        "support", "help", "docs", "login", "secure", "vpn", "remote"
    ]

    for name in common_names:
        host = f"{name}.{domain}"
        try:
            socket.gethostbyname(host)
            subdomains.add(host)
        except Exception:
            pass

    result = {"subdomains": sorted(subdomains)}

    # If at least one source worked, show warnings but do not mark total failure.
    if errors:
        result["warning"] = "; ".join(errors[:4])

    # Only show error if absolutely nothing was found.
    if not subdomains and errors:
        result["error"] = "Subdomain sources failed or returned no data: " + "; ".join(errors[:4])

    return result

# ════════════════════════════════════════════════════════════
#  STEP 4 — IP RESOLUTION + GEOLOCATION
#  Determines the approximate physical location of the server
# ════════════════════════════════════════════════════════════
def run_ip_geo(domain):
    """
    IP Geolocation estimates the server location from its IP address.
    ip-api.com returns details such as city, country, ISP, latitude,
    longitude, timezone, and ASN information.
    """
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"error": f"DNS resolution failed: {e}"}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "ip":        ip,
                "city":      data.get("city", "N/A"),
                "region":    data.get("regionName", "N/A"),
                "country":   data.get("country", "N/A"),
                "isp":       data.get("isp", "N/A"),
                "org":       data.get("org", "N/A"),
                "lat":       data.get("lat", "N/A"),
                "lon":       data.get("lon", "N/A"),
                "timezone":  data.get("timezone", "N/A"),
                "as":        data.get("as", "N/A"),
            }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
    return {"ip": ip}


# ════════════════════════════════════════════════════════════
#  STEP 5 — TECH STACK DETECTION
#  Detects technologies used by the website
# ════════════════════════════════════════════════════════════
def run_tech_detect(domain):
    """
    HTTP response headers and page content can reveal website technology.

    This module attempts to identify:
    - Web server type, such as Apache, Nginx, or IIS
    - Programming language or framework
    - CMS indicators, such as WordPress, Joomla, or Drupal
    - CDN or cache providers, such as Cloudflare or CloudFront
    """
    techs = []
    headers_raw = {}
    try:
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    timeout=8,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=True
                )
                headers_raw = dict(resp.headers)
                break
            except Exception:
                continue

        h = {k.lower(): v.lower() for k, v in headers_raw.items()}
        body = ""
        try:
            r2 = requests.get(f"https://{domain}", timeout=8,
                              headers={"User-Agent": "Mozilla/5.0"})
            body = r2.text.lower()
        except Exception:
            pass

        # Web Server
        if "server" in h:
            techs.append(f"Server: {headers_raw.get('Server', '')}")

        # Programming language / framework
        checks = {
            "x-powered-by":     headers_raw.get("X-Powered-By", ""),
            "x-generator":      headers_raw.get("X-Generator", ""),
            "x-drupal-cache":   "Drupal CMS",
            "x-joomla":        "Joomla CMS",
        }
        for hdr, val in checks.items():
            if hdr in h and val:
                techs.append(f"Powered By: {val}")

        # CDN / Security
        if "cf-ray" in h:          techs.append("CDN: Cloudflare")
        if "x-amz-cf-id" in h:     techs.append("CDN: Amazon CloudFront")
        if "x-cache" in h:         techs.append(f"Cache: {headers_raw.get('X-Cache','')}")
        if "strict-transport-security" in h: techs.append("Security: HSTS Enabled")
        if "content-security-policy" in h:   techs.append("Security: CSP Enabled")
        if "x-frame-options" in h:           techs.append("Security: X-Frame-Options Set")

        # Body-based detection
        if "wp-content" in body:    techs.append("CMS: WordPress")
        if "joomla" in body:        techs.append("CMS: Joomla")
        if "drupal" in body:        techs.append("CMS: Drupal")
        if "react" in body:         techs.append("Frontend: React.js")
        if "vue.js" in body:        techs.append("Frontend: Vue.js")
        if "angular" in body:       techs.append("Frontend: Angular")
        if "jquery" in body:        techs.append("Library: jQuery")
        if "bootstrap" in body:     techs.append("CSS: Bootstrap")

    except Exception as e:
        return {"error": str(e), "techs": [], "headers": {}}

    return {
        "techs":   techs if techs else ["No common tech signatures detected"],
        "headers": headers_raw
    }


# ════════════════════════════════════════════════════════════
#  STEP 6 — SECURITY HEADERS ANALYZER
#  Analyzes HTTP security headers and generates a score
# ════════════════════════════════════════════════════════════
def run_security_headers(domain):
    """
    Security Headers Analyzer
    Checks important HTTP security headers and generates a weighted
    score with a letter grade. Weighted scoring gives more realistic
    results than giving every header the same value.
    """
    security_headers = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security",
            "purpose": "Forces HTTPS and helps protect against SSL stripping attacks.",
            "weight": 20
        },
        "content-security-policy": {
            "name": "Content-Security-Policy",
            "purpose": "Reduces the risk of XSS and malicious script injection.",
            "weight": 20
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "purpose": "Provides protection against clickjacking attacks.",
            "weight": 15
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "purpose": "Blocks browser MIME sniffing.",
            "weight": 15
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "purpose": "Controls referrer information leakage.",
            "weight": 10
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "purpose": "Restricts browser permissions such as camera, microphone, and geolocation.",
            "weight": 10
        },
        "cross-origin-opener-policy": {
            "name": "Cross-Origin-Opener-Policy",
            "purpose": "Improves cross-origin window isolation.",
            "weight": 5
        },
        "cross-origin-resource-policy": {
            "name": "Cross-Origin-Resource-Policy",
            "purpose": "Protects resources from unauthorized cross-origin access.",
            "weight": 5
        }
    }

    informational_headers = {
        "server": {
            "name": "Server",
            "purpose": "Server banner exposure detected. It is usually better to hide or minimize this value."
        },
        "x-powered-by": {
            "name": "X-Powered-By",
            "purpose": "Application technology disclosure detected. This can reveal stack information."
        },
        "cache-control": {
            "name": "Cache-Control",
            "purpose": "Controls browser and proxy caching. Useful for reviewing sensitive content handling."
        }
    }

    results = {
        "present": [],
        "missing": [],
        "informational": [],
        "score": 0,
        "grade": "F",
        "raw_headers": {},
        "url_checked": "N/A",
        "score_method": "Weighted security header score"
    }

    try:
        response = None
        last_error = None
        for scheme in ("https", "http"):
            try:
                response = requests.get(
                    f"{scheme}://{domain}",
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=True
                )
                results["url_checked"] = response.url
                break
            except Exception as e:
                last_error = e
                continue

        if response is None:
            return {"error": f"Unable to connect using HTTP or HTTPS: {last_error}"}

        headers = dict(response.headers)
        results["raw_headers"] = headers
        lower_headers = {k.lower(): v for k, v in headers.items()}

        score = 0
        for key, info in security_headers.items():
            if key in lower_headers:
                score += info["weight"]
                results["present"].append({
                    "header": info["name"],
                    "value": lower_headers[key],
                    "purpose": info["purpose"],
                    "weight": info["weight"]
                })
            else:
                results["missing"].append({
                    "header": info["name"],
                    "purpose": info["purpose"],
                    "weight": info["weight"]
                })

        for key, info in informational_headers.items():
            if key in lower_headers:
                results["informational"].append({
                    "header": info["name"],
                    "value": lower_headers[key],
                    "purpose": info["purpose"]
                })

        results["score"] = min(score, 100)

        if score >= 90:
            results["grade"] = "A+"
        elif score >= 80:
            results["grade"] = "A"
        elif score >= 70:
            results["grade"] = "B"
        elif score >= 60:
            results["grade"] = "C"
        elif score >= 40:
            results["grade"] = "D"
        else:
            results["grade"] = "F"

    except Exception as e:
        results["error"] = str(e)

    return results


# ════════════════════════════════════════════════════════════
#  STEP 7 — HTML REPORT GENERATOR
#  Generates a professional HTML report
# ════════════════════════════════════════════════════════════
def generate_report(domain, all_data):
    """
    Converts all gathered intelligence into a professional HTML report
    that can be opened in a browser, printed, or shared.
    """
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = f"osint_{domain.replace('.','_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    whois_data = all_data.get("whois", {})
    dns_data   = all_data.get("dns",   {})
    sub_data   = all_data.get("subdomains", {})
    geo_data   = all_data.get("geo",   {})
    tech_data  = all_data.get("tech",  {})
    headers_data = all_data.get("headers", {})

    def row(label, value):
        return f"<tr><td class='lbl'>{label}</td><td class='val'>{value}</td></tr>"

    def section(title, color, content):
        return f"""
        <div class="section">
          <div class="sec-header" style="border-left:4px solid {color}">
            <span style="color:{color}">{title}</span>
          </div>
          {content}
        </div>"""

    # WHOIS table
    whois_html = "<table>"
    for k, v in whois_data.items():
        if isinstance(v, list):
            v = "<br>".join(str(x) for x in v)
        whois_html += row(k.replace("_", " ").upper(), v)
    whois_html += "</table>"

    # DNS table
    dns_html = "<table>"
    for rtype, vals in dns_data.items():
        if isinstance(vals, list) and vals:
            dns_html += row(rtype, "<br>".join(str(v) for v in vals))
        elif isinstance(vals, str):
            dns_html += row(rtype, vals)
    dns_html += "</table>"

    # Subdomains
    subs = sub_data.get("subdomains", [])
    sub_html = f"<p style='color:#aaa;margin:0 0 8px'>Found <b style='color:#00d4ff'>{len(subs)}</b> subdomains</p>"
    sub_html += "<div class='tag-wrap'>" + "".join(
        f"<span class='tag'>{s}</span>" for s in subs
    ) + "</div>"

    # Geo table
    geo_html = "<table>"
    for k, v in geo_data.items():
        geo_html += row(k.upper(), v)
    geo_html += "</table>"

    # Tech table
    techs = tech_data.get("techs", [])
    tech_html = "<div class='tag-wrap'>" + "".join(
        f"<span class='tag' style='border-color:#a78bfa;color:#a78bfa'>{t}</span>"
        for t in techs
    ) + "</div>"

    # Security Headers table
    headers_html = "<table>"
    headers_html += row("URL CHECKED", headers_data.get("url_checked", "N/A"))
    headers_html += row("SECURITY SCORE", f"{headers_data.get('score', 0)}/100")
    headers_html += row("GRADE", headers_data.get("grade", "F"))
    headers_html += row("SCORING METHOD", headers_data.get("score_method", "Weighted security header score"))

    present_headers = headers_data.get("present", [])
    missing_headers = headers_data.get("missing", [])
    informational_headers = headers_data.get("informational", [])

    if present_headers:
        headers_html += row(
            "PRESENT HEADERS",
            "<br>".join([f"{h['header']} (+{h.get('weight', 0)} pts) : {h['value']}" for h in present_headers])
        )
    else:
        headers_html += row("PRESENT HEADERS", "None detected")

    if missing_headers:
        headers_html += row(
            "MISSING HEADERS",
            "<br>".join([f"{h['header']} (-{h.get('weight', 0)} pts) — {h['purpose']}" for h in missing_headers])
        )
    else:
        headers_html += row("MISSING HEADERS", "None")

    if informational_headers:
        headers_html += row(
            "INFORMATIONAL HEADERS",
            "<br>".join([f"{h['header']} : {h['value']} — {h['purpose']}" for h in informational_headers])
        )

    headers_html += "</table>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PHANTOM-EYE Report — {domain}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ background:#080c10; color:#c9d1d9; font-family:'Courier New',monospace; padding:30px }}
  .header {{ background:#0d1117; border:1px solid #21262d; border-radius:8px;
             padding:24px 32px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:center }}
  .brand {{ font-size:28px; font-weight:bold; color:#e6edf3; letter-spacing:2px }}
  .brand span {{ color:#ff3040 }}
  .meta {{ text-align:right; color:#8b949e; font-size:11px; line-height:1.8 }}
  .meta b {{ color:#00d4ff }}
  .section {{ background:#0d1117; border:1px solid #21262d; border-radius:8px;
              padding:20px 24px; margin-bottom:18px }}
  .sec-header {{ font-size:13px; font-weight:bold; letter-spacing:2px;
                 padding-left:12px; margin-bottom:16px }}
  table {{ width:100%; border-collapse:collapse }}
  td {{ padding:8px 12px; border-bottom:1px solid #161b22; font-size:12px }}
  .lbl {{ color:#8b949e; width:200px; text-transform:uppercase; letter-spacing:1px }}
  .val {{ color:#c9d1d9 }}
  .tag-wrap {{ display:flex; flex-wrap:wrap; gap:8px }}
  .tag {{ background:#161b22; border:1px solid #00d4ff; color:#00d4ff;
          padding:4px 12px; border-radius:20px; font-size:11px }}
  .footer {{ text-align:center; color:#3a3a3a; font-size:10px; margin-top:24px }}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="brand">PHANTOM<span>-</span>EYE</div>
    <div style="color:#8b949e;font-size:11px;margin-top:4px">DIGITAL FORENSICS AND OSINT INTELLIGENCE PLATFORM</div>
  </div>
  <div class="meta">
    <div>TARGET  <b>{domain}</b></div>
    <div>GENERATED  <b>{ts}</b></div>
    <div>ANALYST  <b>Muhammad Ammar Ansari</b></div>
    <div>ORG  <b>Nexora Cyber Tech</b></div>
  </div>
</div>

{section("WHOIS  —  DOMAIN REGISTRATION INFO", "#00d4ff", whois_html)}
{section("DNS RECORDS  —  DOMAIN NAME SYSTEM", "#39d353", dns_html)}
{section("SUBDOMAIN ENUMERATION  —  crt.sh", "#ff8c00", sub_html)}
{section("IP GEOLOCATION  —  SERVER LOCATION", "#ff3040", geo_html)}
{section("TECHNOLOGY STACK DETECTION", "#a78bfa", tech_html)}
{section("SECURITY HEADERS ANALYSIS", "#ff79c6", headers_html)}

<div class="footer">
  PHANTOM-EYE v1.0  ·  Open Source OSINT Reconnaissance Platform  ·  {ts}<br>
  This report is for authorized security testing only.
</div>
</body>
</html>"""

    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)
    return fname


# ════════════════════════════════════════════════════════════
#  STEP 6 — PHANTOM-EYE GUI
# ════════════════════════════════════════════════════════════
class PhantomEyeGUI:
    def __init__(self, root):
        self.root      = root
        self.root.title("PHANTOM-EYE  ·  Digital Forensics OSINT Platform")
        self.root.geometry("1160x720")
        self.root.configure(bg=BG_DEEP)
        self.root.minsize(900, 600)

        self._log_queue  = []
        self._all_data   = {}
        self._scanning   = False

        self._build_header()
        self._build_body()
        self._build_footer()
        self._poll_queue()
        self._tick()

    # ── Layout ─────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG_PANEL, height=72)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Left brand
        left = tk.Frame(hdr, bg=BG_PANEL)
        left.pack(side="left", padx=(18, 0), fill="y")
        tk.Frame(left, bg=CYAN, width=4).pack(
            side="left", fill="y", padx=(0, 14), pady=10)
        txt = tk.Frame(left, bg=BG_PANEL)
        txt.pack(side="left", pady=12)
        tk.Label(txt, text="PHANTOM-EYE",
                 font=("Courier", 22, "bold"), fg=WHITE, bg=BG_PANEL
                 ).pack(anchor="w")
        tk.Label(txt, text="DIGITAL FORENSICS AND OSINT INTELLIGENCE PLATFORM  v1.0",
                 font=("Courier", 7), fg=GRAY, bg=BG_PANEL
                 ).pack(anchor="w")

        # Right clock
        right = tk.Frame(hdr, bg=BG_PANEL)
        right.pack(side="right", padx=20, fill="y", pady=14)
        self.clock_lbl = tk.Label(right, text="",
                                  font=("Courier", 13, "bold"),
                                  fg=CYAN, bg=BG_PANEL)
        self.clock_lbl.pack(anchor="e")
        tk.Label(right, text="M Ammar Ansari  ·  Digital Forensics",
                 font=("Courier", 7), fg=GRAY, bg=BG_PANEL).pack(anchor="e")

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

    def _build_body(self):
        # Target input bar
        bar = tk.Frame(self.root, bg=BG_CARD, height=52)
        bar.pack(fill="x", padx=14, pady=(12, 0))
        bar.pack_propagate(False)

        tk.Label(bar, text="  TARGET DOMAIN :",
                 font=("Courier", 10, "bold"), fg=GRAY, bg=BG_CARD
                 ).pack(side="left", padx=(14, 0))

        self.domain_var = tk.StringVar(value="example.com")
        entry = tk.Entry(bar,
                         textvariable=self.domain_var,
                         font=("Courier", 13, "bold"),
                         fg=CYAN, bg=BG_DEEP,
                         insertbackground=CYAN,
                         bd=0, relief="flat", width=28)
        entry.pack(side="left", padx=14, ipady=6)
        entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = tk.Button(
            bar, text="  LAUNCH RECON  ",
            font=("Courier", 10, "bold"),
            fg=BG_DEEP, bg=GREEN,
            activeforeground=BG_DEEP, activebackground="#2a9d3a",
            bd=0, relief="flat", cursor="hand2",
            command=self._start_scan
        )
        self.scan_btn.pack(side="left", padx=(0, 8), pady=10)

        self.report_btn = tk.Button(
            bar, text="  EXPORT REPORT  ",
            font=("Courier", 10, "bold"),
            fg=BG_DEEP, bg=AMBER,
            activeforeground=BG_DEEP, activebackground="#cc7000",
            bd=0, relief="flat", cursor="hand2",
            command=self._export_report, state="disabled"
        )
        self.report_btn.pack(side="left", pady=10)

        self.progress_lbl = tk.Label(bar, text="",
                                     font=("Courier", 8), fg=GRAY, bg=BG_CARD)
        self.progress_lbl.pack(side="right", padx=16)

        # Main body (sidebar + log)
        body = tk.Frame(self.root, bg=BG_DEEP)
        body.pack(fill="both", expand=True, padx=14, pady=10)
        self._build_sidebar(body)
        self._build_log(body)

    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=BG_PANEL, width=230)
        sb.pack(side="left", fill="y", padx=(0, 12))
        sb.pack_propagate(False)

        # Module status cards
        tk.Label(sb, text="  RECON MODULES",
                 font=("Courier", 8, "bold"), fg=GRAY, bg=BG_PANEL
                 ).pack(anchor="w", pady=(12, 6), padx=10)

        self._mod_labels = {}
        modules = [
            ("whois",      "WHOIS Lookup",       CYAN),
            ("dns",        "DNS Records",         GREEN),
            ("subdomains", "Subdomain Enum",      AMBER),
            ("geo",        "IP Geolocation",      RED),
            ("tech",       "Tech Detection",      PURPLE),
            ("headers",    "Security Headers",    PINK),
        ]
        for key, name, color in modules:
            card = tk.Frame(sb, bg=BORDER)
            card.pack(fill="x", padx=10, pady=3)
            inner = tk.Frame(card, bg=BG_CARD)
            inner.pack(fill="both", padx=1, pady=1)

            row = tk.Frame(inner, bg=BG_CARD)
            row.pack(fill="x", padx=12, pady=8)

            dot = tk.Label(row, text="[ ]", font=("Courier", 8),
                           fg="#2a2a2a", bg=BG_CARD)
            dot.pack(side="left")
            tk.Label(row, text=f"  {name}",
                     font=("Courier", 9), fg=DIM, bg=BG_CARD
                     ).pack(side="left")
            stat = tk.Label(row, text="IDLE",
                            font=("Courier", 7, "bold"),
                            fg="#333", bg=BG_CARD)
            stat.pack(side="right")
            self._mod_labels[key] = (dot, stat, color)

        # Summary card
        tk.Label(sb, text="  SUMMARY",
                 font=("Courier", 8, "bold"), fg=GRAY, bg=BG_PANEL
                 ).pack(anchor="w", pady=(16, 6), padx=10)

        sc = tk.Frame(sb, bg=BORDER)
        sc.pack(fill="x", padx=10)
        sc_inner = tk.Frame(sc, bg=BG_CARD)
        sc_inner.pack(fill="both", padx=1, pady=1)

        self._summary_items = {}
        for label, key in [("Subdomains", "subs"),
                            ("DNS Records", "dns_count"),
                            ("Emails Found", "emails"),
                            ("Technologies", "techs"),
                            ("Header Score", "header_score")]:
            r = tk.Frame(sc_inner, bg=BG_CARD)
            r.pack(fill="x", padx=12, pady=5)
            tk.Label(r, text=label, font=("Courier", 8),
                     fg=GRAY, bg=BG_CARD).pack(side="left")
            val = tk.Label(r, text="—", font=("Courier", 9, "bold"),
                           fg=CYAN, bg=BG_CARD)
            val.pack(side="right")
            self._summary_items[key] = val

    def _build_log(self, parent):
        lf = tk.Frame(parent, bg=BG_DEEP)
        lf.pack(side="right", fill="both", expand=True)

        bar = tk.Frame(lf, bg=BG_PANEL, height=34)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text="  [>] INTELLIGENCE OUTPUT",
                 font=("Courier", 9, "bold"), fg=CYAN, bg=BG_PANEL
                 ).pack(side="left", padx=6, pady=8)
        tk.Button(bar, text="CLEAR", font=("Courier", 7, "bold"),
                  fg=GRAY, bg=BG_CARD, bd=0, padx=8, pady=2,
                  activeforeground=WHITE, activebackground=BORDER,
                  relief="flat", cursor="hand2",
                  command=self._clear_log
                  ).pack(side="right", padx=10, pady=6)

        tk.Frame(lf, bg=BORDER, height=1).pack(fill="x")

        self.log = scrolledtext.ScrolledText(
            lf, font=("Courier", 10),
            fg=GREEN, bg="#090f09",
            insertbackground=CYAN,
            bd=0, relief="flat", wrap=tk.WORD, padx=14, pady=10
        )
        self.log.pack(fill="both", expand=True)

        # Colour tags
        tags = {
            "head":    CYAN,    "ok":     GREEN,
            "warn":    AMBER,   "err":    RED,
            "purple":  PURPLE,  "gray":   GRAY,
            "white":   WHITE,   "dim":    "#4a5568,",
            "data":    DIM,
        }
        for tag, color in tags.items():
            self.log.tag_configure(tag, foreground=color.rstrip(","))

        self._ilog("PHANTOM-EYE initialized. Enter a domain and click LAUNCH RECON.\n", "gray")
        self.log.configure(state="disabled")

    def _build_footer(self):
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")
        foot = tk.Frame(self.root, bg=BG_PANEL, height=24)
        foot.pack(fill="x")
        foot.pack_propagate(False)
        self.status_bar = tk.Label(foot, text="Ready.",
                                   font=("Courier", 7), fg=GRAY, bg=BG_PANEL)
        self.status_bar.pack(side="left", padx=14)
        tk.Label(foot,
                 text="PHANTOM-EYE  (c)2025  Open Source OSINT Reconnaissance Platform",
                 font=("Courier", 7), fg="#2a2a2a", bg=BG_PANEL
                 ).pack(side="right", padx=14)

    # ── Logging helpers ────────────────────────────────────

    def _ilog(self, text, tag="ok"):
        self.log.configure(state="normal")
        self.log.insert(tk.END, text, tag)
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _queue_log(self, text, tag="ok"):
        self._log_queue.append((text, tag))

    def _poll_queue(self):
        while self._log_queue:
            text, tag = self._log_queue.pop(0)
            self._ilog(text, tag)
        self.root.after(80, self._poll_queue)

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.configure(state="disabled")

    # ── Module status helpers ──────────────────────────────

    def _set_mod(self, key, state):
        """IDLE → RUNNING → DONE / ERROR"""
        dot, stat, color = self._mod_labels[key]
        if state == "running":
            dot.configure(fg=AMBER, text="[~]")
            stat.configure(text="RUNNING", fg=AMBER)
        elif state == "done":
            dot.configure(fg=color,  text="[+]")
            stat.configure(text="DONE",    fg=color)
        elif state == "error":
            dot.configure(fg=RED,    text="[!]")
            stat.configure(text="ERROR",   fg=RED)
        else:
            dot.configure(fg="#2a2a2a", text="[ ]")
            stat.configure(text="IDLE",    fg="#333")

    def _reset_mods(self):
        for key in self._mod_labels:
            self._set_mod(key, "idle")
        for val in self._summary_items.values():
            val.configure(text="—")

    # ── Clock ──────────────────────────────────────────────

    def _tick(self):
        self.clock_lbl.configure(
            text=datetime.datetime.now().strftime("%H:%M:%S   %d %b %Y"))
        self.root.after(1000, self._tick)

    # ── Main Scan ─────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        domain = self.domain_var.get().strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a valid domain name.")
            return

        self._scanning = True
        self._all_data = {}
        self.report_btn.configure(state="disabled")
        self.scan_btn.configure(state="disabled", fg="#2a3a2a")
        self._reset_mods()
        self._clear_log()

        threading.Thread(target=self._run_all_modules,
                         args=(domain,), daemon=True).start()

    def _run_all_modules(self, domain):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._queue_log(
            f"{'='*58}\n"
            f"  PHANTOM-EYE RECON SESSION\n"
            f"  Target  : {domain}\n"
            f"  Time    : {ts}\n"
            f"{'='*58}\n\n", "head")

        # ── WHOIS ──────────────────────────────────────────
        self.root.after(0, self._set_mod, "whois", "running")
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Step 1/6 — WHOIS Lookup..."})
        self._queue_log("[ STEP 1 ]  WHOIS LOOKUP\n", "head")
        w = run_whois(domain)
        self._all_data["whois"] = w
        if "error" not in w:
            self._queue_log(f"  Registrar    : {w.get('registrar','N/A')}\n", "data")
            self._queue_log(f"  Organization : {w.get('org','N/A')}\n", "data")
            self._queue_log(f"  Country      : {w.get('country','N/A')}\n", "data")
            self._queue_log(f"  Created      : {w.get('creation_date','N/A')}\n", "data")
            self._queue_log(f"  Expires      : {w.get('expiry_date','N/A')}\n", "data")
            self._queue_log(f"  Status       : {w.get('status','N/A')}\n", "data")
            emails = w.get("emails", [])
            if emails:
                self._queue_log(f"  Emails       : {', '.join(emails)}\n", "ok")
                self.root.after(0, self._summary_items["emails"].configure,
                                {"text": str(len(emails))})
            self.root.after(0, self._set_mod, "whois", "done")
        else:
            self._queue_log(f"  [!] {w['error']}\n", "err")
            self.root.after(0, self._set_mod, "whois", "error")
        self._queue_log("\n", "gray")

        # ── DNS ────────────────────────────────────────────
        self.root.after(0, self._set_mod, "dns", "running")
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Step 2/6 — DNS Records..."})
        self._queue_log("[ STEP 2 ]  DNS RECORDS\n", "head")
        d = run_dns(domain)
        self._all_data["dns"] = d
        total_dns = 0
        for rtype, vals in d.items():
            if rtype == "error":
                self._queue_log(f"  [!] {vals}\n", "err")
                continue
            if vals:
                self._queue_log(f"  {rtype:<6} : ", "gray")
                for v in vals:
                    self._queue_log(f"{v}  ", "ok")
                self._queue_log("\n", "ok")
                total_dns += len(vals)
        self.root.after(0, self._summary_items["dns_count"].configure,
                        {"text": str(total_dns)})
        self.root.after(0, self._set_mod, "dns",
                        "done" if "error" not in d else "error")
        self._queue_log("\n", "gray")

        # ── SUBDOMAINS ─────────────────────────────────────
        self.root.after(0, self._set_mod, "subdomains", "running")
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Step 3/6 — Subdomain Enum (may take ~15s)..."})
        self._queue_log("[ STEP 3 ]  SUBDOMAIN ENUMERATION  (via crt.sh)\n", "head")
        s = run_subdomains(domain)
        self._all_data["subdomains"] = s
        subs = s.get("subdomains", [])
        if subs:
            self._queue_log(f"  Found {len(subs)} subdomains:\n", "warn")
            for sub in subs:
                self._queue_log(f"    >> {sub}\n", "ok")
        else:
            self._queue_log("  No subdomains found (or crt.sh timeout)\n", "gray")
        if "error" in s:
            self._queue_log(f"  [!] {s['error']}\n", "err")
        self.root.after(0, self._summary_items["subs"].configure,
                        {"text": str(len(subs))})
        self.root.after(0, self._set_mod, "subdomains",
                        "done" if subs else "error")
        self._queue_log("\n", "gray")

        # ── GEO ────────────────────────────────────────────
        self.root.after(0, self._set_mod, "geo", "running")
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Step 4/6 — IP Geolocation..."})
        self._queue_log("[ STEP 4 ]  IP GEOLOCATION\n", "head")
        g = run_ip_geo(domain)
        self._all_data["geo"] = g
        if "error" not in g:
            self._queue_log(f"  IP Address   : {g.get('ip','N/A')}\n", "warn")
            self._queue_log(f"  Location     : {g.get('city','N/A')}, {g.get('region','N/A')}, {g.get('country','N/A')}\n", "data")
            self._queue_log(f"  ISP          : {g.get('isp','N/A')}\n", "data")
            self._queue_log(f"  Organization : {g.get('org','N/A')}\n", "data")
            self._queue_log(f"  AS Number    : {g.get('as','N/A')}\n", "data")
            self._queue_log(f"  Timezone     : {g.get('timezone','N/A')}\n", "data")
            self._queue_log(f"  Coordinates  : {g.get('lat','N/A')}, {g.get('lon','N/A')}\n", "data")
            self.root.after(0, self._set_mod, "geo", "done")
        else:
            self._queue_log(f"  [!] {g.get('error','Unknown error')}\n", "err")
            self.root.after(0, self._set_mod, "geo", "error")
        self._queue_log("\n", "gray")

        # ── TECH ───────────────────────────────────────────
        self.root.after(0, self._set_mod, "tech", "running")
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Step 5/6 — Tech Stack Detection..."})
        self._queue_log("[ STEP 5 ]  TECHNOLOGY STACK DETECTION\n", "head")
        t = run_tech_detect(domain)
        self._all_data["tech"] = t
        techs = t.get("techs", [])
        for tech in techs:
            self._queue_log(f"  >> {tech}\n", "purple")
        if "error" in t:
            self._queue_log(f"  [!] {t['error']}\n", "err")
        self.root.after(0, self._summary_items["techs"].configure,
                        {"text": str(len(techs))})
        self.root.after(0, self._set_mod, "tech",
                        "done" if techs else "error")
        self._queue_log("\n", "gray")


        # ── SECURITY HEADERS ───────────────────────────────
        self.root.after(0, self._set_mod, "headers", "running")
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Step 6/6 — Security Headers Analysis..."})
        self._queue_log("[ STEP 6 ]  SECURITY HEADERS ANALYSIS\n", "head")
        hsec = run_security_headers(domain)
        self._all_data["headers"] = hsec

        if "error" not in hsec:
            self._queue_log(f"  URL Checked    : {hsec.get('url_checked', 'N/A')}\n", "data")
            self._queue_log(f"  Security Score : {hsec.get('score', 0)}/100\n", "warn")
            self._queue_log(f"  Security Grade : {hsec.get('grade', 'F')}\n", "purple")

            present = hsec.get("present", [])
            missing = hsec.get("missing", [])

            self._queue_log("\n  Present Headers:\n", "ok")
            if present:
                for item in present:
                    self._queue_log(f"    [+] {item['header']} (+{item.get('weight', 0)} pts) : {item['value']}\n", "data")
            else:
                self._queue_log("    None detected\n", "gray")

            self._queue_log("\n  Missing Headers:\n", "err")
            if missing:
                for item in missing:
                    self._queue_log(f"    [-] {item['header']} (-{item.get('weight', 0)} pts) — {item['purpose']}\n", "err")
            else:
                self._queue_log("    None\n", "ok")


            informational = hsec.get("informational", [])
            if informational:
                self._queue_log("\n  Informational Headers:\n", "gray")
                for item in informational:
                    self._queue_log(f"    [i] {item['header']} : {item['value']} — {item['purpose']}\n", "gray")

            self.root.after(0, self._summary_items["header_score"].configure,
                            {"text": f"{hsec.get('score', 0)}%"})
            self.root.after(0, self._set_mod, "headers", "done")
        else:
            self._queue_log(f"  [!] {hsec['error']}\n", "err")
            self.root.after(0, self._summary_items["header_score"].configure,
                            {"text": "ERR"})
            self.root.after(0, self._set_mod, "headers", "error")
        self._queue_log("\n", "gray")

        # ── DONE ───────────────────────────────────────────
        self._queue_log(f"{'='*58}\n", "head")
        self._queue_log(f"  RECON COMPLETE  —  {domain}\n", "ok")
        self._queue_log(f"  Click EXPORT REPORT to save HTML report.\n", "gray")
        self._queue_log(f"{'='*58}\n", "head")

        self._scanning = False
        self.root.after(0, self.scan_btn.configure,
                        {"state": "normal", "fg": BG_DEEP})
        self.root.after(0, self.report_btn.configure, {"state": "normal"})
        self.root.after(0, self.progress_lbl.configure,
                        {"text": "Scan complete!"})
        self.root.after(0, self.status_bar.configure,
                        {"text": f"Recon completed: {domain}  |  {ts}"})

    def _export_report(self):
        if not self._all_data:
            messagebox.showinfo("No Data", "Please run a scan first.")
            return
        domain = self.domain_var.get().strip()
        try:
            fname = generate_report(domain, self._all_data)
            messagebox.showinfo(
                "Report Saved!",
                f"HTML report saved successfully:\n{fname}\n\nOpen it in your browser."
            )
            self.status_bar.configure(text=f"Report saved: {fname}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    root = tk.Tk()
    app  = PhantomEyeGUI(root)
    root.mainloop()
