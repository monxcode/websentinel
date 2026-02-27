# ⚡ WebSentinel Framework

**Advanced Web Application Security Assessment Tool**  
A modular, professional-grade security analysis framework for authorized penetration testers.

---

## ⚠️ Legal Disclaimer

WebSentinel is designed for **authorized security testing only**. You must have **explicit written permission** from the target system owner before scanning. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar laws in your jurisdiction.

---

## Features

- 🔍 **Advanced Crawler Engine** <br> BFS crawl with sitemap.xml, robots.txt parsing, form detection, and endpoint classification (static / dynamic / api / auth / admin)
- 🧠 **Technology Fingerprinting** <br> Passive detection of server, CMS, frameworks, languages, and WAF
- 🛡 **40+ Vulnerability Modules** <br> SQL Injection, XSS, SSRF, LFI, CORS, CSRF, IDOR, Open Redirect, and more
- 📊 **Risk Scoring Engine** <br> Confidence-weighted score (0–100) with letter grade (A–F)
- 📄 **JSON + PDF Reports** <br> Structured JSON output and professional dark-theme PDF report
- 🎨 **Terminal UI** <br> Colored logging, stage indicators, and progress bars via colorama

---

## Installation

#### Clone or extract the project
```bash
cd websentinel_framework
```
#### Install dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

#### Basic passive scan
```bash
python main.py -u https://example.com -p passive
```
#### Balanced scan (recommended)
```bash
python main.py -u https://example.com -p balanced
```
#### Deep safe scan with authentication
```bash
python main.py -u https://example.com -p deep-safe --cookies "session=abc123; token=xyz"
```
#### Custom depth and rate limit
```
python main.py -u https://example.com -p balanced -d 4 --rps 2
```
#### JSON output only
```bash
python main.py -u https://example.com -p passive --json-only
```
#### Verbose mode
```bash
python main.py -u https://example.com -p balanced -v
```

---

## Scan Profiles

| Profile   | Depth | Rate | Injection | Description                              |
|-----------|-------|------|-----------|------------------------------------------|
| passive   | 2     | 1/s  | No        | Passive recon only, no active probing    |
| balanced  | 3     | 3/s  | Yes       | Balanced active + passive analysis       |
| deep-safe | 5     | 5/s  | Yes+Fuzz  | Comprehensive non-destructive deep scan  |

---

## Vulnerability Coverage

| Category            | Modules                                                  |
|---------------------|----------------------------------------------------------|
| Injection           | SQL, NoSQL, Command, LDAP, XML/XXE                       |
| XSS                 | Reflected, Stored, DOM-Based                             |
| CSRF                | Token detection                                          |
| Access Control      | IDOR, Broken Auth, Session Analysis, BAC                 |
| Network             | SSRF, Open Redirect, CORS, Host Header, Cache Poisoning  |
| Security Headers    | HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.       |
| File/Path           | LFI, RFI, Path Traversal, File Upload                   |
| Info Disclosure     | Sensitive files, Hardcoded credentials, Server banners   |
| API Security        | API misconfig, Mass Assignment, Rate Limiting            |
| Crypto              | Weak algorithms, HTTP usage                              |
| Misc                | Clickjacking, Directory Listing, Subdomain Takeover      |

---

## Output

Reports are saved to `./websentinel_output/`:
- `websentinel_report.json` — Machine-readable structured report
- `websentinel_report.pdf` — Professional PDF with charts and remediation guidance

---

## Project Structure

```
websentinel_framework/
├── main.py                    # Entry point & orchestration
├── config.py                  # All configuration & payloads
├── requirements.txt
├── core/
│   ├── crawler.py             # BFS web crawler
│   ├── request_engine.py      # HTTP engine with rate limiting
│   ├── response_analyzer.py   # Response analysis & header checks
│   ├── diff_engine.py         # Response difference detection
│   └── scorer.py              # Risk scoring & grade calculation
├── modules/
│   ├── base_module.py         # Abstract base for all modules
│   ├── injection_modules.py   # SQL, NoSQL, Cmd, LDAP, XML
│   ├── xss_modules.py         # Reflected, Stored, DOM XSS, CSRF
│   ├── access_modules.py      # IDOR, Auth, Session, BAC
│   ├── network_modules.py     # SSRF, OpenRedirect, CORS, Headers
│   ├── file_modules.py        # LFI, RFI, Traversal, Upload, Disclosure
│   └── misc_modules.py        # API, Crypto, Takeover, Cache, etc.
├── intelligence/
│   ├── fingerprint.py         # Tech stack detection
│   ├── endpoint_classifier.py # Endpoint prioritization
│   └── risk_matrix.py         # Risk matrix + remediation DB
├── reports/
│   ├── json_report.py         # JSON report generator
│   └── pdf_report.py          # PDF report generator (ReportLab)
└── utils/
    ├── logger.py              # Colored terminal logger
    └── helpers.py             # URL utilities & helpers
```

---

## License

MIT License — See LICENSE file.  
Use responsibly. Only scan systems you are authorized to test.
