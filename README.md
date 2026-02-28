<div align="center">

```
██╗    ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
╚███╔███╔╝███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

# WebSentinel

**Advanced Web Application Security Assessment Framework**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-1.1.0-00D4AA?style=for-the-badge)](https://github.com/monxcode/websentinel)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-6366F1?style=for-the-badge)]()
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-EF4444?style=for-the-badge)]()

*A modular, non-destructive web vulnerability scanner built for security engineers, penetration testers, and bug bounty hunters.*

[Installation](#installation) · [Usage](#usage) · [Features](#features) · [Documentation](#configuration-options) · [Roadmap](#roadmap)

</div>

---

## Introduction

WebSentinel is a professional-grade web application security assessment framework written in Python. It performs automated, non-destructive vulnerability scanning across 35+ attack categories using a modular architecture designed for scalability and accuracy.

The framework combines intelligent crawling, technology fingerprinting, behavioral anomaly detection, and confidence-weighted risk scoring to produce actionable security reports in both JSON and PDF formats.

WebSentinel is designed for:

- **Security Engineers** running internal application audits
- **Penetration Testers** conducting authorized assessments
- **Bug Bounty Hunters** performing reconnaissance on in-scope targets
- **Developers** validating security posture before production release

---

## Features

| Category | Capability |
|---|---|
| **Crawler** | BFS-based crawler with sitemap.xml parsing, robots.txt support, and form detection |
| **Authentication** | Form-based auto-login with CSRF extraction, direct cookie injection, session verification |
| **Fingerprinting** | Passive detection of server, CMS, frameworks, languages, and WAF |
| **Scanning** | 35+ vulnerability modules across injection, XSS, access control, network, and file categories |
| **Scoring** | Confidence-weighted risk score (0–100) with letter grade (A–F) |
| **Reporting** | Structured JSON output and professional dark-theme PDF with charts and remediation guidance |
| **Rate Control** | Configurable requests/sec, random jitter, per-profile throttling |
| **Safety** | Fully non-destructive — no data modification, mandatory authorization gate |

---

## Vulnerabilities Covered

### Injection

| ID | Module | CWE | Severity |
|---|---|---|---|
| INJ-01 | SQL Injection | CWE-89 | Critical |
| INJ-02 | NoSQL Injection | CWE-943 | High |
| INJ-03 | Command Injection | CWE-78 | Critical |
| INJ-04 | LDAP Injection | CWE-90 | High |
| INJ-05 | XML / XXE Injection | CWE-611 | Critical |

### Cross-Site Attacks

| ID | Module | CWE | Severity |
|---|---|---|---|
| XSS-01 | Reflected XSS | CWE-79 | High |
| XSS-02 | Stored XSS | CWE-79 | Critical |
| XSS-03 | DOM-Based XSS | CWE-79 | Medium |
| XSS-04 | CSRF Token Absence | CWE-352 | Medium |

### Access Control

| ID | Module | CWE | Severity |
|---|---|---|---|
| AC-01 | IDOR | CWE-639 | High |
| AC-02 | Broken Authentication | CWE-523 | High |
| AC-03 | Session Hijacking | CWE-598 | High |
| AC-04 | Broken Access Control | CWE-284 | High |
| AC-05 | Mass Assignment | CWE-269 | High |
| AC-06 | Insecure Deserialization | CWE-502 | High |

### Network & Protocol

| ID | Module | CWE | Severity |
|---|---|---|---|
| NET-01 | SSRF | CWE-918 | Critical |
| NET-02 | Open Redirect | CWE-601 | Medium |
| NET-03 | CORS Misconfiguration | CWE-942 | High |
| NET-04 | Host Header Injection | CWE-113 | High |
| NET-05 | Clickjacking | CWE-1021 | Medium |
| NET-06 | Cache Poisoning | CWE-444 | High |
| NET-07 | Missing Security Headers | CWE-693 | Medium |

### File & Path

| ID | Module | CWE | Severity |
|---|---|---|---|
| FILE-01 | Local File Inclusion (LFI) | CWE-22 | Critical |
| FILE-02 | Remote File Inclusion (RFI) | CWE-98 | Critical |
| FILE-03 | Path Traversal | CWE-22 | Critical |
| FILE-04 | Unrestricted File Upload | CWE-434 | Medium |
| FILE-05 | Directory Listing | CWE-548 | Medium |

### Information Disclosure

| ID | Module | CWE | Severity |
|---|---|---|---|
| INFO-01 | Sensitive File Exposure | CWE-538 | Critical |
| INFO-02 | Hardcoded Credentials | CWE-798 | Critical |
| INFO-03 | Server Banner Disclosure | CWE-200 | Low |
| INFO-04 | Stack Trace Exposure | CWE-200 | Medium |

### Security Configuration

| ID | Module | CWE | Severity |
|---|---|---|---|
| CFG-01 | Weak Cryptography | CWE-327 | Medium |
| CFG-02 | API Misconfiguration | CWE-200 | Medium |
| CFG-03 | Rate Limiting Absent | CWE-307 | Medium |
| CFG-04 | Subdomain Takeover | CWE-285 | Critical |

---

## Installation

### Prerequisites

Ensure Python 3.8 or higher is installed on your system.

```bash
python --version
```

### Step 1 — Clone the Repository

```bash
git clone https://github.com/monxcode/websentinel.git
cd websentinel
```

### Step 2 — Create a Virtual Environment

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows**

```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Verify Installation

```bash
python main.py --help
```

---

## Requirements

| Package | Version | Purpose |
|---|---|---|
| `requests` | ≥ 2.31.0 | HTTP request engine |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing and form detection |
| `colorama` | ≥ 0.4.6 | Cross-platform terminal colors |
| `reportlab` | ≥ 4.0.4 | PDF report generation |
| `lxml` | ≥ 4.9.0 | XML and sitemap parsing |
| `urllib3` | ≥ 2.0.0 | HTTP connection pooling |

**System Requirements**

| Component | Minimum |
|---|---|
| Python | 3.8+ |
| RAM | 512 MB |
| Disk | 100 MB |
| OS | Linux, Windows 10+, macOS 10.14+ |

---

## Usage

### Basic Scan

```bash
python main.py -u https://target.com -p balanced
```

### Passive Reconnaissance

```bash
python main.py -u https://target.com -p passive
```

### Deep Scan

```bash
python main.py -u https://target.com -p deep-safe -d 4
```

### Form-Based Authentication

WebSentinel will automatically discover the login form, extract CSRF tokens, submit credentials, and carry the resulting session through the entire scan.

```bash
python main.py -u https://target.com/login -p balanced --login "username=admin&password=secret"
```

```bash
python main.py -u https://target.com/login -p balanced --login "email=admin@target.com&password=Admin@123"
```

### Session Cookie Injection

Inject a session cookie directly. No additional token is required.

```bash
python main.py -u https://target.com -p balanced --cookies "session=abc123"
```

```bash
python main.py -u https://target.com -p balanced --cookies "PHPSESSID=abc123; user_id=42; role=admin"
```

### Scan After Login with Custom Scan Target

```bash
python main.py -u https://target.com/login -p balanced \
  --login "username=admin&password=secret" \
  --scan-url https://target.com/dashboard
```

### Authenticated Scan with Verification

```bash
python main.py -u https://target.com/login -p deep-safe \
  --login "username=admin&password=secret" \
  --auth-verify
```

### Login and Cookie Combined

```bash
python main.py -u https://target.com/login -p balanced \
  --login "username=admin&password=secret" \
  --cookies "remember_me=1"
```

### Custom Rate Limit and Output Directory

```bash
python main.py -u https://target.com -p balanced --rps 1 --delay 2 --output-dir ./reports
```

### JSON Report Only

```bash
python main.py -u https://target.com -p balanced --json-only
```

### Verbose Debug Mode

```bash
python main.py -u https://target.com -p balanced -v
```

### Ignore robots.txt

```bash
python main.py -u https://target.com -p balanced --no-robots
```

---

## Configuration Options

### Scan Profiles

| Profile | Depth | Rate | Injection | Fuzzing | Recommended For |
|---|---|---|---|---|---|
| `passive` | 2 | 1 rps | No | No | Production systems, initial recon |
| `balanced` | 3 | 3 rps | Yes | No | Standard assessments, bug bounty |
| `deep-safe` | 5 | 5 rps | Yes | Yes | Staging environments, full audits |

### Command Line Reference

**Target**

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | Required | Target URL. Use the login page URL when `--login` is specified |
| `--scan-url` | Auto-resolved | URL to crawl after authentication |

**Scan Settings**

| Flag | Default | Description |
|---|---|---|
| `-p`, `--profile` | `balanced` | Scan profile: `passive`, `balanced`, or `deep-safe` |
| `-d`, `--depth` | Profile default | Crawl depth override |
| `--no-robots` | `False` | Ignore robots.txt disallow rules |

**Authentication**

| Flag | Default | Description |
|---|---|---|
| `--login` | — | Credential string for form-based login (`field=value&field=value`) |
| `--cookies` | — | Session cookie string (`name=value; name=value`) |
| `--auth-verify` | `False` | Verify session is active before scanning begins |

**Request Engine**

| Flag | Default | Description |
|---|---|---|
| `--rps` | Profile default | Maximum requests per second |
| `--delay` | Profile default | Fixed delay in seconds between requests |
| `--timeout` | `15` | Request timeout in seconds |

**Output**

| Flag | Default | Description |
|---|---|---|
| `--output-dir` | `websentinel_output` | Directory for generated reports |
| `--json-only` | `False` | Skip PDF and generate JSON only |
| `--no-pdf` | `False` | Skip PDF report generation |
| `-v`, `--verbose` | `False` | Enable debug-level output |

---

## Project Structure

```
websentinel/
│
├── main.py                          Entry point and scan orchestration
├── config.py                        Payloads, signatures, thresholds, profiles
├── requirements.txt                 Python dependencies
├── LICENSE
│
├── core/
│   ├── auth_handler.py              Form login, cookie injection, session verification
│   ├── crawler.py                   BFS web crawler with form and link extraction
│   ├── diff_engine.py               Baseline vs probe response comparison
│   ├── request_engine.py            HTTP engine with throttling and retry logic
│   ├── response_analyzer.py         Header, cookie, and pattern analysis
│   └── scorer.py                    Risk scoring and letter grade calculation
│
├── modules/
│   ├── base_module.py               Abstract base class for all vulnerability modules
│   ├── injection_modules.py         SQL, NoSQL, Command, LDAP, XML injection
│   ├── xss_modules.py               Reflected, Stored, DOM XSS and CSRF
│   ├── access_modules.py            IDOR, Broken Auth, Session, Access Control
│   ├── network_modules.py           SSRF, Open Redirect, CORS, Headers, Clickjacking
│   ├── file_modules.py              LFI, RFI, Path Traversal, File Upload, Disclosure
│   └── misc_modules.py              API config, Mass Assignment, Crypto, Takeover
│
├── intelligence/
│   ├── endpoint_classifier.py       Endpoint type detection and module routing
│   ├── fingerprint.py               Technology stack and WAF detection
│   └── risk_matrix.py               Risk matrix and OWASP remediation database
│
├── reports/
│   ├── json_report.py               Structured JSON report generator
│   └── pdf_report.py                Professional PDF report with charts
│
└── utils/
    ├── helpers.py                   URL normalization, deduplication, utilities
    └── logger.py                    Colored terminal logger with ASCII banner
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.py                                  │
│                    Scan Orchestrator                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
  │ AuthHandler  │  │  Fingerprint │  │  CrawlerEngine   │
  │              │  │  Engine      │  │                  │
  │ Form Login   │  │              │  │ BFS Crawler      │
  │ Cookie Inject│  │ Server / CMS │  │ Sitemap Parser   │
  │ CSRF Capture │  │ Framework    │  │ Form Detector    │
  │ Verification │  │ WAF          │  │ Endpoint Map     │
  └──────┬───────┘  └──────────────┘  └────────┬─────────┘
         │                                      │
         ▼                                      ▼
  ┌──────────────┐                    ┌──────────────────┐
  │  Request     │◄───────────────────│ Endpoint         │
  │  Engine      │                    │ Classifier       │
  │              │                    │                  │
  │ Rate Limiter │                    │ Type Detection   │
  │ Retry Logic  │                    │ Module Routing   │
  │ Session Mgmt │                    │ Priority Scoring │
  └──────┬───────┘                    └──────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────────────────┐
  │                  Vulnerability Modules               │
  │                                                      │
  │  injection_modules   xss_modules   access_modules    │
  │  network_modules     file_modules  misc_modules      │
  └──────────────────────────────┬───────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                    ▼            ▼            ▼
             ┌──────────┐ ┌──────────┐ ┌──────────────┐
             │  Diff    │ │  Risk    │ │   Reports    │
             │  Engine  │ │  Scorer  │ │              │
             │          │ │          │ │ json_report  │
             │ Baseline │ │ 0–100    │ │ pdf_report   │
             │ Anomaly  │ │ Grade A–F│ │              │
             └──────────┘ └──────────┘ └──────────────┘
```

**Scan Pipeline — 8 Stages**

| Stage | Name | Description |
|---|---|---|
| 01 | Initialize | Request engine, session, rate limiter setup |
| 02 | Authenticate | Form login or cookie injection, session validation |
| 03 | Fingerprint | Passive server, CMS, framework, and WAF detection |
| 04 | Crawl | BFS endpoint discovery via links, sitemaps, and forms |
| 05 | Classify | Endpoint type assignment and module recommendation |
| 06 | Scan | Vulnerability modules run in priority order |
| 07 | Score | Confidence-weighted risk calculation and grading |
| 08 | Report | JSON and PDF report generation |

---

## Output / Report Example

### Terminal Output

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    STAGE 03  ►  TECHNOLOGY FINGERPRINTING
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [10:14:22] [SUCCESS] ✔  Server      : nginx/1.24.0
  [10:14:22] [SUCCESS] ✔  CMS         : WordPress 6.4
  [10:14:22] [SUCCESS] ✔  Frameworks  : React, jQuery
  [10:14:22] [SUCCESS] ✔  Languages   : PHP, JavaScript
  [10:14:22] [INFO   ] ℹ  WAF         : Cloudflare

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    STAGE 06  ►  VULNERABILITY SCANNING
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [10:17:43] [VULN   ] 🔥 CRITICAL : SQL Injection → /post?id=1  (param: id)
  [10:17:51] [VULN   ] 🔥 HIGH     : Reflected XSS → /search?q=  (param: q)
  [10:18:04] [VULN   ] 🔥 HIGH     : CORS Misconfiguration → /api/data
  [10:18:12] [VULN   ] 🔥 MEDIUM   : Missing Content-Security-Policy header
  [10:18:19] [SAFE   ] 🛡  SAFE    : CSRF tokens present on all forms

  ╔══════════════════════════════════════════════╗
  ║         WEBSENTINEL SCAN COMPLETE            ║
  ╠══════════════════════════════════════════════╣
  ║ Target          : https://target.com         ║
  ║ Profile         : balanced                   ║
  ║ Auth Mode       : Form Login                 ║
  ║ Session Cookies : 2                          ║
  ║ Scan Duration   : 14m 22s                    ║
  ║ Requests Made   : 1,043                      ║
  ║                                              ║
  ║ Endpoints       : 178                        ║
  ║ Total Findings  : 21                         ║
  ║                                              ║
  ║   Critical      : 3                          ║
  ║   High          : 7                          ║
  ║   Medium        : 8                          ║
  ║   Low           : 3                          ║
  ║                                              ║
  ║ Security Score  : 44 / 100                   ║
  ║ Security Grade  : D                          ║
  ╚══════════════════════════════════════════════╝
```

### Security Grade Scale

| Score | Grade | Meaning |
|---|---|---|
| 90 – 100 | **A** | Excellent security posture |
| 75 – 89 | **B** | Good, minor issues present |
| 60 – 74 | **C** | Moderate risk, action recommended |
| 40 – 59 | **D** | Poor security, immediate attention required |
| 0 – 39 | **F** | Critical risk, emergency remediation required |

### JSON Report Structure

```json
{
  "websentinel_report": {
    "version": "1.1.0",
    "target": "https://target.com",
    "scan_profile": "balanced",
    "scan_date": "2025-01-15T10:14:22",
    "total_endpoints": 178,
    "total_findings": 21,
    "security_score": 44,
    "security_grade": "D",
    "authentication": {
      "auth_method": "form",
      "success": true,
      "session_cookies": ["sessionid", "csrftoken"],
      "csrf_token_found": true
    },
    "technology_fingerprint": {
      "server": "nginx/1.24.0",
      "cms": "WordPress 6.4",
      "frameworks": ["React", "jQuery"],
      "languages": ["PHP", "JavaScript"],
      "waf": "Cloudflare"
    },
    "risk_distribution": {
      "critical": 3,
      "high": 7,
      "medium": 8,
      "low": 3,
      "info": 0
    },
    "vulnerabilities": [
      {
        "type": "SQLInjection",
        "severity": "critical",
        "title": "SQL Injection in parameter 'id'",
        "url": "https://target.com/post?id=1",
        "parameter": "id",
        "evidence": "MySQL syntax error detected in response body",
        "confidence": 92,
        "cwe": "CWE-89",
        "cvss": 9.8,
        "remediation": "Use parameterized queries or prepared statements"
      }
    ]
  }
}
```

### PDF Report Sections

The generated PDF report includes:

1. **Cover Page** — Target, scan profile, security score, and grade
2. **Executive Summary** — Non-technical overview for stakeholders
3. **Attack Surface Overview** — Endpoint type distribution table
4. **Risk Distribution** — Pie chart and severity breakdown
5. **Technology Fingerprint** — Full detected stack
6. **Detailed Findings** — Per-vulnerability evidence and context
7. **Risk Matrix** — All findings prioritized by severity and confidence
8. **Remediation Guidance** — OWASP-aligned fix recommendations per vulnerability type

### Report File Location

```
websentinel_output/
├── websentinel_report.json
└── websentinel_report.pdf
```

---

## Security Disclaimer

> **WebSentinel is intended exclusively for authorized security testing.**

Before running WebSentinel against any target, you must have one of the following:

- Ownership of the target system
- Explicit written authorization from the system owner
- A signed scope document from a client engagement
- Written acceptance from a bug bounty program covering the target

**Unauthorized scanning is illegal** and may violate:

- Information Technology Act, 2000 — India (Section 43, 66)
- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act — United Kingdom
- EU Directive on Attacks Against Information Systems

WebSentinel is a **non-destructive** tool. It does not modify, delete, or exfiltrate data. All requests are read-only observations of application behavior.

The authors of WebSentinel accept no liability for misuse of this software.

---

## Roadmap

| Status | Feature |
|---|---|
| ✅ Done | 35+ vulnerability scanning modules |
| ✅ Done | Form-based authentication with CSRF capture |
| ✅ Done | Session cookie injection without mandatory token |
| ✅ Done | JSON and PDF dual reporting |
| ✅ Done | Technology fingerprinting (server, CMS, WAF, framework) |
| ✅ Done | Confidence-weighted risk scoring (0–100) |
| 🔄 In Progress | GraphQL introspection and injection testing |
| 🔄 In Progress | WebSocket endpoint scanning |
| 📋 Planned | Headless browser mode (Playwright) for JavaScript-heavy SPAs |
| 📋 Planned | CI/CD integration plugin (GitHub Actions, GitLab CI) |
| 📋 Planned | Multi-threaded parallel scanning engine |
| 📋 Planned | Custom payload injection from external file |
| 📋 Planned | Continuous monitoring mode with delta reports |
| 📋 Planned | HTML report format |
| 📋 Planned | Plugin/extension system for custom modules |
| 📋 Planned | Automatic login detection (no manual --login required) |

---

## Contributing

Contributions are welcome. Please follow the guidelines below.

### Getting Started

```bash
git clone https://github.com/monxcode/websentinel.git
cd websentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Adding a Vulnerability Module

1. Create a class that inherits from `BaseModule` in the appropriate `modules/*.py` file
2. Implement the `run(endpoint)` method returning `List[Finding]`
3. Use `self._should_inject()` to respect the active scan profile
4. Register the module in `get_scan_modules()` inside `main.py`
5. Add remediation guidance to `REMEDIATION_DB` in `intelligence/risk_matrix.py`

### Pull Request Guidelines

- One feature or fix per pull request
- Follow existing code style and naming conventions
- Test against a local vulnerable application (DVWA, WebGoat, or Juice Shop)
- Update this README if new flags or modules are added

### Reporting Bugs

Open an issue with the following information:

- Python version and OS
- Command used
- Target type (local lab, staging, etc.)
- Full terminal output with `-v` flag enabled

---


## Contact

**Author:** Mohan Singh Parmar

[![GitHub](https://img.shields.io/badge/GitHub-monxcode-181717?style=for-the-badge&logo=github)](https://github.com/monxcode)

For security vulnerabilities in WebSentinel itself, please open a private GitHub issue rather than a public one.

---

<div align="center">

*Built for security professionals. Use responsibly.*

**⚡ WebSentinel — Scan with purpose. Report with clarity. Fix with confidence.**

</div>