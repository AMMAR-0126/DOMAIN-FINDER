# 👁️ PHANTOM-EYE — OSINT Reconnaissance Automation Tool

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Stars](https://img.shields.io/github/stars/AMMAR-0126/Vulnerability_Scanner?style=social)

> **PHANTOM-EYE** is a GUI-based OSINT (Open Source Intelligence) tool that automates domain reconnaissance using only publicly available data sources — no intrusive scanning, no exploits.

**Author:** M Ammar Ansari | **Company:** Digital Forensics | **Version:** 1.0

---

## ✨ Features

- 🔍 **WHOIS Lookup** — Domain registration, registrar, organization, expiry dates & emails
- 🌐 **DNS Records** — A, AAAA, MX, NS, TXT, CNAME record enumeration
- 🗂️ **Subdomain Enumeration** — Multi-source discovery via crt.sh, CertSpotter & HackerTarget
- 📍 **IP Geolocation** — City, country, ISP, ASN, timezone & coordinates
- 🛠️ **Tech Stack Detection** — Web server, CMS, CDN, frontend frameworks & libraries
- 🔒 **Security Headers Analyzer** — Weighted score (0–100) with letter grade (A+ to F)
- 📄 **HTML Report Export** — Professional report saved as a browser-ready HTML file

---

## 🔬 Reconnaissance Modules (6 Steps)

### Step 1 — WHOIS Lookup
Retrieves domain registration details from the public WHOIS database.

| Field | Description |
|-------|-------------|
| Registrar | Domain registrar name |
| Organization | Registered organization |
| Country | Registration country |
| Creation Date | Domain creation date |
| Expiry Date | Domain expiration date |
| Name Servers | DNS name servers |
| Emails | Public contact emails |
| Status | Domain status (e.g. clientTransferProhibited) |

---

### Step 2 — DNS Records
Maps the domain to its DNS infrastructure.

| Record | Description |
|--------|-------------|
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | Mail exchange servers |
| NS | Authoritative name servers |
| TXT | SPF, DKIM, DMARC verification records |
| CNAME | Alias records |

---

### Step 3 — Subdomain Enumeration
Discovers public subdomains using 4 independent sources:

- **crt.sh** — Certificate Transparency logs (primary source)
- **CertSpotter API** — Public CT log aggregator
- **HackerTarget** — hostsearch API
- **DNS Resolution** — Common name wordlist fallback

---

### Step 4 — IP Geolocation
Resolves the target IP and retrieves its physical location via `ip-api.com`.

Returns: City, Region, Country, ISP, Organization, Latitude, Longitude, Timezone, AS Number.

---

### Step 5 — Tech Stack Detection
Analyzes HTTP headers and page source to fingerprint technologies:

| Category | Examples Detected |
|----------|------------------|
| Web Server | Apache, Nginx, IIS |
| CMS | WordPress, Joomla, Drupal |
| CDN | Cloudflare, Amazon CloudFront |
| Frontend | React.js, Vue.js, Angular |
| Libraries | jQuery, Bootstrap |
| Security | HSTS, CSP, X-Frame-Options |

---

### Step 6 — Security Headers Analyzer
Checks HTTP security headers and generates a **weighted security score**.

| Header | Weight | Protection Against |
|--------|--------|-------------------|
| Strict-Transport-Security | 20 pts | SSL stripping attacks |
| Content-Security-Policy | 20 pts | XSS & script injection |
| X-Frame-Options | 15 pts | Clickjacking |
| X-Content-Type-Options | 15 pts | MIME sniffing |
| Referrer-Policy | 10 pts | Referrer leakage |
| Permissions-Policy | 10 pts | Camera/mic/geo misuse |
| Cross-Origin-Opener-Policy | 5 pts | Window isolation |
| Cross-Origin-Resource-Policy | 5 pts | Unauthorized resource access |

**Grading Scale:**

| Score | Grade |
|-------|-------|
| 90–100 | A+ |
| 80–89 | A |
| 70–79 | B |
| 60–69 | C |
| 40–59 | D |
| 0–39 | F |

---

## 🛠️ Requirements

### System
```bash
sudo apt install python3 python3-pip python3-tk
```

### Python Libraries
```bash
pip install requests python-whois dnspython
```

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/AMMAR-0126/Vulnerability_Scanner.git

# Navigate into the folder
cd Vulnerability_Scanner

# Install dependencies
pip install requests python-whois dnspython

# Run the tool
python3 osint_tool.py
```

---

## 🚀 Usage

```bash
python3 osint_tool.py
```

1. Enter a target domain in the input field (e.g. `example.com`)
2. Click **▶ START SCAN**
3. Watch all 6 modules run in real time with color-coded output
4. View the summary panel for key metrics
5. Click **EXPORT REPORT** to save a professional HTML report

---

## 📁 Project Structure

```
Vulnerability_Scanner/
├── osint_tool.py       # Main application (single-file, all-in-one)
├── README.md           # Documentation
└── reports/            # HTML reports saved here after export
```

---

## 🎨 Output Color Coding

| Color | Meaning |
|-------|---------|
| 🔵 Cyan | Step headers & IP addresses |
| 🟢 Green | Successful results & open findings |
| 🟠 Amber | Warnings & notable items |
| 🔴 Red | Errors & missing security headers |
| 🟣 Purple | Technology detections |
| ⚪ Gray | Informational / neutral output |

---

## ⚠️ Disclaimer

> This tool is intended for **educational purposes** and **authorized security research only.**
> It uses **publicly available data sources** only — no intrusive scanning or exploitation.
> Do **NOT** use this tool against any domain without **explicit written permission.**
> The developer is **not responsible** for any misuse or damage caused by this tool.
> Always comply with your local laws and ethical guidelines.

---

## 👨‍💻 Author

**M Ammar Ansari** — Digital Forensics
- 🐙 GitHub: [@AMMAR-0126](https://github.com/AMMAR-0126)
- 🔗 Repository: [Vulnerability_Scanner](https://github.com/AMMAR-0126/Vulnerability_Scanner)

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute.

---

<div align="center">
⭐ <b>If you found this useful, please give it a star!</b> ⭐
</div>
