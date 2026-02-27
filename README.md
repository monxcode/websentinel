<div align="center">

```
 ██╗    ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ╚███╔███╔╝███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

# ⚡ WebSentinel Framework

**Advanced Web Application Security Assessment Tool**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)]()
[![Security](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red?style=flat-square)]()

*A modular, professional-grade security analysis framework for ethical penetration testers, bug bounty hunters, and security researchers.*

</div>

---

## 🚨 Legal Disclaimer — PLEASE READ FIRST

> **WebSentinel Framework sirf authorized security testing ke liye banaya gaya hai.**

Is tool ka use karne se pehle aapko yeh confirm karna zaroori hai:

- ✅ Aapke paas **target system owner ki EXPLICIT written permission** hai
- ✅ Aap khud system ke owner hain (apni website test kar rahe hain)
- ✅ Aap ek authorized penetration tester hain (signed contract/scope ke saath)
- ✅ Aap bug bounty program ke scope mein test kar rahe hain

**Bina permission ke scanning illegal hai aur in laws ke under punishable hai:**
- 🇮🇳 Information Technology Act, 2000 (India) — Section 43, 66
- 🇺🇸 Computer Fraud and Abuse Act (CFAA) — United States
- 🇬🇧 Computer Misuse Act — United Kingdom
- 🇪🇺 EU Directive on Attacks Against Information Systems

> ⚠️ Tool ke authors kisi bhi misuse ke liye liable nahi hain. Tool start hone par aapko ek legal confirmation prompt milega — sirf "yes" type karein agar aap authorized hain.

---

## 📋 Table of Contents

1. [Changelog](#changelog)
2. [Tool Overview](#tool-overview)
3. [Key Features](#key-features)
4. [System Requirements](#system-requirements)
5. [Installation Guide](#installation-guide)
   - [Windows Installation](#windows-installation)
   - [Linux / macOS Installation](#linux--macos-installation)
   - [Virtual Environment Setup (Recommended)](#virtual-environment-setup-recommended)
   - [Verify Installation](#verify-installation)
6. [Quick Start](#quick-start)
7. [Scan Profiles](#scan-profiles)
8. [All Command Line Options](#all-command-line-options)
9. [Detailed Usage Guide](#detailed-usage-guide)
   - [Basic Scans](#1-basic-scans)
   - [Authenticated Scans](#2-authenticated-scans) ⭐ *Updated*
     - [Mode A — Form-Based Auto-Login](#-mode-a--form-based-auto-login---login)
     - [Mode B — Direct Cookie Injection](#-mode-b--direct-cookie-injection---cookies)
     - [Mode C — Session Verification](#-mode-c--session-verification---auth-verify)
     - [Testing Common Platforms](#-testing-common-platforms)
   - [Custom Rate Limiting](#3-custom-rate-limiting)
   - [Bug Bounty Workflow](#4-bug-bounty-workflow)
   - [API Security Testing](#5-api-security-testing)
   - [Own Website Testing](#6-own-website-testing)
10. [Understanding Scan Output](#understanding-scan-output)
11. [Reports Guide](#reports-guide)
12. [Vulnerability Coverage](#vulnerability-coverage)
13. [Scan Stages Explained](#scan-stages-explained)
14. [Project Structure](#project-structure)
15. [Configuration Guide](#configuration-guide)
16. [Troubleshooting](#troubleshooting)
17. [Use Cases](#use-cases)
18. [FAQ](#faq)

## 📅 Changelog

---

### v1.1.0 — Authentication System Update *(Latest)*

> **feat: add authentication system with login support and improved session handling**

#### ✅ New Features

| Feature | Flag | Description |
|---------|------|-------------|
| **Form-based auto-login** | `--login "user=x&pass=y"` | WebSentinel automatically discovers login form, extracts CSRF token, submits credentials, and captures session |
| **Session cookie support** | `--cookies "session=abc"` | Inject session cookies directly — **no mandatory token required** |
| **Post-login scan URL** | `--scan-url https://...` | Specify where to scan after login (auto-resolved if omitted) |
| **Session verification** | `--auth-verify` | Verify session is active before scan begins |
| **Combined auth modes** | `--login + --cookies` | Use form login AND pre-set cookies together |

#### 🔧 Fixes

- **Fixed**: Session cookie not working properly — cookies now injected directly via `session.cookies.set()` without requiring any token
- **Fixed**: Auth cookies were not persisting across redirects — requests session now properly maintains cookie jar
- **Fixed**: CSRF token detection was breaking non-CSRF forms — now optional and graceful

#### 🆕 New Files

- `core/auth_handler.py` — Complete authentication engine with `AuthHandler` class and `parse_cookie_string()` utility

#### ♻️ Changed

- `core/request_engine.py` — Added `apply_cookies()`, `update_headers()`, `get_active_cookies()` methods
- `main.py` — New `--login`, `--scan-url`, `--auth-verify` flags; Auth stage added as Stage 2
- `reports/json_report.py` — Authentication summary included in JSON output
- `reports/pdf_report.py` — Auth method shown in executive summary key metrics

#### 💡 Example Commands (New in v1.1.0)

```bash
# Login with credentials (auto-discovers form + CSRF)
python main.py -u https://example.com/login -p balanced \
  --login "username=admin&password=admin123"

# Scan with session cookie — no token needed
python main.py -u https://example.com -p balanced \
  --cookies "session=abc123"

# Cookie-only scan (works without CSRF token)
python main.py -u https://example.com -p deep-safe \
  --cookies "session=xyz456"

# Login + verify + deep scan
python main.py -u https://example.com/login -p deep-safe \
  --login "username=admin&password=secret" \
  --auth-verify
```

---

### v1.0.0 — Initial Release

- Advanced BFS crawler with sitemap.xml + robots.txt support
- 35+ vulnerability modules (SQLi, XSS, SSRF, LFI, CORS, and more)
- Technology fingerprinting (server, CMS, framework, WAF)
- Risk scoring engine (0–100) with letter grade (A–F)
- JSON + PDF dual report generation
- Colored terminal UI with ASCII banner

---

## 🔭 Tool Overview

WebSentinel Framework ek **Python-based terminal tool** hai jo automatically website ki security vulnerabilities dhundta hai. Yeh tool:

- Website ko crawl karta hai aur sare endpoints/pages discover karta hai
- Har endpoint par **35+ vulnerability checks** chalata hai
- Results ko score (0-100) aur grade (A-F) mein convert karta hai
- Professional **JSON + PDF reports** generate karta hai

### Yeh tool kaise kaam karta hai?

```
Target URL Input
      │
      ▼
┌─────────────────┐
│  Legal Confirm  │  ← Aapki authorization confirm karta hai
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Tech Fingerprint│  ← Server, CMS, Framework detect karta hai
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Web Crawler    │  ← Sare pages, forms, APIs dhundta hai
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 35+ Vuln Scans  │  ← Har page par security checks
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Risk Scoring   │  ← Score calculate, grade assign
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ JSON + PDF Report│  ← Professional reports save
└─────────────────┘
```

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🕷️ **Smart Crawler** | BFS-based crawler jo sitemap.xml, robots.txt, forms, aur hidden endpoints discover karta hai |
| 🧠 **Tech Fingerprinting** | Server, CMS (WordPress/Drupal/etc), frameworks, languages, aur WAF passive detection |
| 🔍 **35+ Vuln Modules** | SQL Injection se lekar Cache Poisoning tak — sab non-destructive |
| ⚖️ **Risk Scoring** | Confidence-weighted 0-100 score + A-F grade with full distribution |
| 📄 **Dual Reports** | Structured JSON (machine-readable) + Dark-theme professional PDF |
| 🎨 **Rich Terminal UI** | Colorful ASCII banner, stage indicators, real-time progress bars |
| 🔒 **Rate Limiting** | Configurable requests/sec with random jitter to avoid overloading |
| 🔑 **Auth Support** | Cookie-based authenticated session testing |
| 🛡️ **Non-Destructive** | Sirf observe karta hai — koi data delete/modify nahi karta |
| 🧩 **Modular Design** | Har vulnerability ek alag module — easily extendable |

---

## 💻 System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10/11, Ubuntu 18.04+, macOS 10.14+, Kali Linux |
| **Python** | 3.8 or higher |
| **RAM** | 512 MB minimum (1 GB recommended) |
| **Storage** | 100 MB free space |
| **Network** | Active internet connection to target |
| **Permissions** | Normal user (no root/admin required) |

### Python Version Check karo

```bash
python --version
# ya
python3 --version
```

Agar Python 3.8+ installed hai toh aage badho. Nahi toh pehle install karo:
- **Windows**: https://www.python.org/downloads/
- **Ubuntu/Debian**: `sudo apt install python3 python3-pip`
- **macOS**: `brew install python3`
- **Kali Linux**: Python3 already installed hota hai

---

## 🛠️ Installation Guide

### Windows Installation

**Step 1: Python install karo**
```cmd
:: Python official site se download karo
:: https://www.python.org/downloads/
:: Installation mein "Add Python to PATH" checkbox zaroor tick karo
```

**Step 2: Project folder mein jao**
```cmd
cd websentinel_framework
```

**Step 3: Virtual environment banao (recommended)**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Step 4: Dependencies install karo**
```cmd
pip install -r requirements.txt
```

**Step 5: Test karo**
```cmd
python main.py --help
```

---

### Linux / macOS Installation

**Step 1: System packages update karo**
```bash
# Ubuntu/Debian/Kali
sudo apt update && sudo apt install python3 python3-pip python3-venv git -y

# CentOS/RHEL/Fedora
sudo dnf install python3 python3-pip -y

# macOS (Homebrew)
brew install python3
```

**Step 2: Project folder mein jao**
```bash
cd websentinel_framework
```

**Step 3: Dependencies install karo**
```bash
pip3 install -r requirements.txt
```

**Step 4: Test karo**
```bash
python3 main.py --help
```

---

### Virtual Environment Setup (Recommended)

Virtual environment use karna best practice hai — yeh aapke system Python ko affect nahi karta.

```bash
# ─── Linux / macOS ───────────────────────────────
cd websentinel_framework

# Virtual environment banao
python3 -m venv venv

# Activate karo
source venv/bin/activate

# Dependencies install karo
pip install -r requirements.txt

# Jab kaam khatam ho, deactivate karo
deactivate

# ─── Windows ─────────────────────────────────────
cd websentinel_framework

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

> 💡 **Tip**: Har baar tool use karne se pehle virtual environment activate karo.

---

### Verify Installation

Sabhi dependencies sahi install hui hain ya nahi, yeh check karo:

```bash
python3 -c "
import requests
import bs4
import colorama
import reportlab
print('✅ requests     OK')
print('✅ beautifulsoup4 OK')
print('✅ colorama     OK')
print('✅ reportlab    OK')
print()
print('🎉 Sab dependencies sahi install hain!')
"
```

Agar koi error aaye:
```bash
# Individual package install karo
pip install requests
pip install beautifulsoup4
pip install colorama
pip install reportlab
pip install lxml
pip install urllib3
```

---

## 🚀 Quick Start

Pehli baar use karne ke liye:

```bash
# Apni khud ki website test karo (SIRF authorized target!)
python3 main.py -u https://yourdomain.com -p passive

# Tool start hoga → Legal disclaimer dikhega → "yes" type karo → Scan shuru
```

**Expected output:**
```
╔══════════════════════════════════════╗
║     LEGAL DISCLAIMER & WARNING      ║
╚══════════════════════════════════════╝

  Do you have EXPLICIT authorization to scan this target? [yes/NO]: yes

  [STAGE 01] Initializing Engines
  [STAGE 02] Technology Fingerprinting
  [STAGE 03] Web Crawling & Endpoint Discovery
  [STAGE 04] Endpoint Classification
  [STAGE 05] Vulnerability Scanning
  [STAGE 06] Risk Scoring
  [STAGE 07] Report Generation

  ╔══════════════════════════════╗
  ║   WEBSENTINEL SCAN COMPLETE  ║
  ╠══════════════════════════════╣
  ║ Security Score : 72/100      ║
  ║ Security Grade : C           ║
  ╚══════════════════════════════╝
```

Reports `websentinel_output/` folder mein save hongi.

---

## 📊 Scan Profiles

WebSentinel mein **3 scan profiles** hain — target aur requirement ke hisaab se choose karo:

### `passive` — Sirf Dekho, Chuo Mat
```bash
python3 main.py -u https://example.com -p passive
```
- **Kya karta hai**: Sirf observe karta hai, koi payload nahi bhejta
- **Depth**: 2 levels
- **Speed**: 1 request/second
- **Best for**: Production systems jo sensitive hain, initial reconnaissance
- **Checks**: Security headers, tech fingerprinting, cookie flags, info disclosure
- **Risk**: Almost zero — like a normal browser visit

### `balanced` — Default, Recommended
```bash
python3 main.py -u https://example.com -p balanced
```
- **Kya karta hai**: Active vulnerability testing with safe payloads
- **Depth**: 3 levels
- **Speed**: 3 requests/second
- **Best for**: Regular security assessments, bug bounty programs
- **Checks**: SQL injection, XSS, SSRF, CORS, headers, session analysis, + sab passive checks
- **Risk**: Low — non-destructive payloads use hote hain

### `deep-safe` — Comprehensive Full Scan
```bash
python3 main.py -u https://example.com -p deep-safe
```
- **Kya karta hai**: Full parameter fuzzing + sab vulnerability modules
- **Depth**: 5 levels
- **Speed**: 5 requests/second
- **Best for**: Dedicated pentest environments, CTF, staging servers
- **Checks**: Sab modules + parameter fuzzing + full endpoint enumeration
- **Risk**: Medium — zyada requests jaate hain, WAF trigger ho sakta hai

| Profile | Depth | Speed | Injection | Fuzzing | Use Case |
|---------|-------|-------|-----------|---------|----------|
| passive | 2 | 1 rps | ❌ | ❌ | Recon only |
| balanced | 3 | 3 rps | ✅ | ❌ | Standard pentest |
| deep-safe | 5 | 5 rps | ✅ | ✅ | Full assessment |

---

## ⚙️ All Command Line Options

```bash
python3 main.py [OPTIONS]
```

### Target Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--url` | `-u` | Required | Target URL. When `--login` is used, this is the **login page URL** |
| `--scan-url` | — | Auto | URL to crawl after login. Defaults to base domain of `--url` |

### Scan Settings

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--profile` | `-p` | `balanced` | Scan profile: `passive` / `balanced` / `deep-safe` |
| `--depth` | `-d` | Profile default | Crawl depth override |
| `--no-robots` | — | False | Ignore robots.txt disallow rules |

### Authentication Options *(New in v1.1.0)*

| Option | Default | Description |
|--------|---------|-------------|
| `--login "user=x&pass=y"` | — | **Form-based auto-login** — WebSentinel finds the form, adds CSRF token, logs in, captures session |
| `--cookies "name=val"` | — | **Direct cookie injection** — session cookie without needing any token |
| `--auth-verify` | False | Verify session is active before scanning |

> ✅ `--cookies` works with just a session cookie — **no CSRF token or additional token required**.  
> ✅ `--login` and `--cookies` can be **combined** (e.g., login + pre-set remember_me cookie).

### Request Engine

| Option | Default | Description |
|--------|---------|-------------|
| `--rps` | Profile default | Max requests per second |
| `--delay` | Profile default | Fixed delay in seconds between requests |
| `--timeout` | `15` | Request timeout in seconds |

### Output

| Option | Default | Description |
|--------|---------|-------------|
| `--output-dir` | `websentinel_output` | Report output directory |
| `--json-only` | False | Skip PDF, generate JSON only |
| `--no-pdf` | False | Skip PDF report |
| `--verbose` / `-v` | False | Debug output |

### Quick Option Examples

```bash
# Custom depth
python3 main.py -u https://example.com -p balanced -d 5

# Very slow scan (production)
python3 main.py -u https://example.com -p passive --rps 0.5 --delay 3

# Custom output folder
python3 main.py -u https://example.com -p balanced --output-dir ./my_reports

# Slow + verbose debug
python3 main.py -u https://example.com -p balanced --rps 1 -v

# Skip PDF, JSON only
python3 main.py -u https://example.com -p passive --json-only

# robots.txt ignore + deep scan
python3 main.py -u https://example.com -p deep-safe --no-robots
```

---

## 📖 Detailed Usage Guide

### 1. Basic Scans

#### Apni website ka quick health check
```bash
python3 main.py -u https://mywebsite.com -p passive
```
> Yeh scan ~2-3 minutes mein complete hoga aur basic security issues batayega.

#### Standard security assessment
```bash
python3 main.py -u https://mywebsite.com -p balanced
```
> ~10-20 minutes, sab major vulnerabilities check karega.

#### Full comprehensive scan
```bash
python3 main.py -u https://mywebsite.com -p deep-safe -d 4
```
> ~30-60 minutes, maximum coverage.

---

### 2. Authenticated Scans

WebSentinel v1.1.0 mein **2 authentication modes** hain:

---

#### 🔑 Mode A — Form-Based Auto-Login (`--login`)

WebSentinel khud login form dhundega, CSRF token capture karega, credentials submit karega, aur resulting session cookies ko automatically scan mein use karega.

```bash
# Basic login — standard username/password fields
python3 main.py -u https://example.com/login -p balanced \
  --login "username=admin&password=admin123"

# Email-based login
python3 main.py -u https://example.com/login -p balanced \
  --login "email=admin@example.com&password=Admin@123"

# Custom field names (WebSentinel auto-maps them)
python3 main.py -u https://example.com/auth -p balanced \
  --login "user_email=admin@site.com&user_password=secret123"

# Login + specify where to scan after (if login and app are different paths)
python3 main.py -u https://example.com/login -p balanced \
  --login "username=admin&password=secret" \
  --scan-url https://example.com/dashboard

# Login + extra cookies combined (e.g., remember_me flag)
python3 main.py -u https://example.com/login -p deep-safe \
  --login "username=admin&password=secret" \
  --cookies "remember_me=1; theme=dark"
```

**Yeh kaise kaam karta hai (internally):**
```
1. GET login page  →  form discover karta hai
2. CSRF token automatically extract karta hai (agar hai toh)
3. POST credentials (with CSRF token) → login submit
4. Redirect / response analyze karta hai → success/failure detect
5. Session cookies capture → session mein apply
6. --scan-url ya base domain se crawl shuru
```

> 💡 **Auto-detection**: WebSentinel automatically `username`, `email`, `user`, `login` jaise field names detect karta hai. Aapko field names manually specify nahi karne padte.

---

#### 🍪 Mode B — Direct Cookie Injection (`--cookies`)

Agar aapke paas already session cookie hai (browser se copy ki hui), toh directly inject karo. **Koi token ya CSRF required nahi** — sirf cookie string dena hai.

```bash
# Single session cookie — no token needed
python3 main.py -u https://example.com -p balanced \
  --cookies "session=abc123"

# Cookie without any token — works perfectly
python3 main.py -u https://example.com -p deep-safe \
  --cookies "session=xyz456"

# PHP session cookie
python3 main.py -u https://example.com -p balanced \
  --cookies "PHPSESSID=abc123def456"

# Django session
python3 main.py -u https://django-app.com -p balanced \
  --cookies "sessionid=abcdef123456"

# Multiple cookies (semicolon-separated)
python3 main.py -u https://app.example.com -p balanced \
  --cookies "PHPSESSID=abc123; user_id=42; role=admin"

# WordPress admin scan
python3 main.py -u https://myblog.com -p balanced \
  --cookies "wordpress_logged_in_abc=user%7C1234%7Ctoken; wp-settings-1=mfolded"

# JWT token as cookie
python3 main.py -u https://api.example.com -p balanced \
  --cookies "access_token=eyJhbGciOiJIUzI1NiJ9.abc.xyz"
```

**Cookie kaise copy karein (browser se):**
```
Chrome / Edge:
  1. F12 → Application tab
  2. Storage → Cookies → apna domain
  3. Name + Value copy karo

Firefox:
  1. F12 → Storage tab
  2. Cookies → apna domain
  3. Name + Value copy karo

Ya: curl ke saath login karo aur -c flag se cookies save karo:
  curl -c cookies.txt -d "username=admin&password=secret" https://example.com/login
  # Ab cookie file se value copy karo
```

---

#### 🔒 Mode C — Session Verification (`--auth-verify`)

Scan se pehle verify karo ki session actually authenticated hai:

```bash
python3 main.py -u https://example.com -p balanced \
  --cookies "session=abc123" \
  --auth-verify
```

Output mein dikhega:
```
  [SUCCESS] ✔  Session verified: Authenticated session confirmed
  [INFO   ] ℹ  Active session cookies (1): ['session']
```

---

#### 🔗 Mode Combination — Login + Pre-set Cookies

Dono modes saath use karo jab login ke saath kuch extra cookies bhi chahiye:

```bash
# Login karao + additional cookies inject karo
python3 main.py -u https://example.com/login -p balanced \
  --login "username=admin&password=secret" \
  --cookies "remember_token=xyz; analytics_opt=1"
```

---

#### 📋 Authentication in Reports

Har report (JSON + PDF) mein authentication summary included hoti hai:

```json
"authentication": {
  "auth_method": "form",
  "success": true,
  "login_url": "https://example.com/login",
  "post_login_url": "https://example.com/dashboard",
  "session_cookies": ["sessionid", "csrftoken"],
  "csrf_token_found": true
}
```

---

#### 🧪 Testing Common Platforms

```bash
# ── WordPress ─────────────────────────────────────────────
python3 main.py -u https://myblog.com/wp-login.php -p balanced \
  --login "log=admin&pwd=admin123"

# ── Django (auto-discovers csrfmiddlewaretoken) ──────────
python3 main.py -u https://django-app.com/accounts/login -p balanced \
  --login "username=admin&password=admin123"

# ── Laravel (auto-discovers _token) ──────────────────────
python3 main.py -u https://laravel-app.com/login -p balanced \
  --login "email=admin@example.com&password=admin123"

# ── Generic PHP app ──────────────────────────────────────
python3 main.py -u https://php-app.com/login.php -p balanced \
  --login "username=admin&password=admin123" \
  --cookies "PHPSESSID=pre_existing_session"

# ── DVWA (local testing lab) ──────────────────────────────
python3 main.py -u http://localhost/dvwa/login.php -p deep-safe \
  --login "username=admin&password=password" \
  --cookies "security=low"

# ── WebGoat (local testing lab) ──────────────────────────
python3 main.py -u http://localhost:8080/WebGoat/login -p deep-safe \
  --login "username=guest&password=guest"
```

---

### 3. Custom Rate Limiting

Slow server ya production system ke liye:

```bash
# Bahut slow scan (1 request har 3 seconds)
python3 main.py -u https://example.com -p balanced --rps 0.33 --delay 3

# Medium speed
python3 main.py -u https://example.com -p balanced --rps 2

# Faster scan (only if you have permission and server can handle it)
python3 main.py -u https://example.com -p deep-safe --rps 10
```

> ⚠️ Production servers par zyada speed mat use karo — server down ho sakta hai.

---

### 4. Bug Bounty Workflow

Bug bounty programs ke liye recommended workflow:

```bash
# Step 1: Initial passive recon (always start here)
python3 main.py -u https://target.com -p passive \
  --output-dir ./recon_phase

# Step 2: Active balanced scan
python3 main.py -u https://target.com -p balanced \
  --output-dir ./active_scan

# Step 3: Authenticated scan with --login (create free account first)
python3 main.py -u https://target.com/login -p balanced \
  --login "username=youruser&password=yourpass" \
  --output-dir ./auth_scan

# Step 4: Authenticated scan with session cookie
python3 main.py -u https://target.com -p balanced \
  --cookies "session=your_session_here" \
  --output-dir ./cookie_scan

# Step 5: API deep scan
python3 main.py -u https://api.target.com -p deep-safe \
  --cookies "Authorization=Bearer your_jwt_token" \
  --output-dir ./api_scan
```

> 📋 **Tip**: Reports mein findings ko program ke disclosure guidelines ke hisaab se report karo. JSON report machine-readable hai — isko automation mein use kar sakte ho.

---

### 5. API Security Testing

REST API endpoints test karne ke liye:

```bash
# API base URL target karo
python3 main.py -u https://api.example.com -p balanced \
  --cookies "Authorization=Bearer eyJhbGc..." \
  --no-robots

# Deep API scan
python3 main.py -u https://api.example.com/v1 -p deep-safe \
  --cookies "api_key=your_key_here" \
  -d 3
```

WebSentinel API endpoints ke liye automatically check karta hai:
- `/api/`, `/v1/`, `/v2/`, `/graphql`, `/rest/` patterns
- Debug endpoints: `/actuator`, `/swagger`, `/health`, `/metrics`
- Mass assignment, rate limiting, authentication bypass

---

### 6. Own Website Testing (Self-Assessment)

Apni website ki security regularly check karo:

```bash
# Local development server
python3 main.py -u http://localhost:8000 -p deep-safe

# Staging environment (production se pehle)
python3 main.py -u https://staging.myapp.com -p deep-safe \
  --output-dir ./security_audit_$(date +%Y%m%d)

# Production (sirf passive — careful!)
python3 main.py -u https://myapp.com -p passive \
  --rps 1 --delay 2
```

---

## 📈 Understanding Scan Output

### Terminal Output During Scan

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    STAGE 01  ►  INITIALIZING ENGINES
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [10:23:45] [INFO   ] ℹ  Target       : https://example.com
  [10:23:45] [INFO   ] ℹ  Profile      : balanced
  [10:23:46] [SUCCESS] ✔  Server      : Apache/2.4.51
  [10:23:46] [SUCCESS] ✔  CMS         : WordPress
  [10:23:48] [INFO   ] ℹ  Sitemap: 45 URLs discovered
  [10:23:52] [VULN   ] 🔥 HIGH: Reflected XSS in parameter 'q' @ /search?q=
  [10:23:55] [VULN   ] 🔥 CRITICAL: SQL Injection in parameter 'id' @ /post?id=
  [10:24:01] [SAFE   ] 🛡  CORS properly configured on /api/data
```

### Log Level Colors

| Color | Level | Meaning |
|-------|-------|---------|
| 🔵 Cyan | INFO | General information |
| 🟢 Green | SUCCESS | Successful check / Safe |
| 🟡 Yellow | WARNING | Potential issue |
| 🔴 Red | ERROR | Error / Critical Finding |
| 🟣 Magenta | CRITICAL | Critical vulnerability |
| 🔴 Red | VULN | Vulnerability found |
| 🟢 Green | SAFE | No vulnerability |

### Final Summary Box

```
  ╔═══════════════════════════════════════════════╗
  ║          WEBSENTINEL SCAN COMPLETE            ║
  ╠═══════════════════════════════════════════════╣
  ║ Target          : https://example.com         ║
  ║ Profile         : balanced                    ║
  ║ Scan Duration   : 12m 34s                     ║
  ║ Requests Made   : 847                         ║
  ║                                               ║
  ║ Endpoints       : 124                         ║
  ║ Total Findings  : 23                          ║
  ║                                               ║
  ║   Critical      : 2                           ║
  ║   High          : 5                           ║
  ║   Medium        : 9                           ║
  ║   Low           : 7                           ║
  ║                                               ║
  ║ Security Score  : 48/100                      ║
  ║ Security Grade  : D                           ║
  ╚═══════════════════════════════════════════════╝
```

### Security Score Explained

| Score | Grade | Meaning | Action Required |
|-------|-------|---------|-----------------|
| 90–100 | **A** | Excellent security posture | Minor improvements, keep monitoring |
| 75–89 | **B** | Good, few issues | Fix medium/low findings |
| 60–74 | **C** | Moderate risk | Prioritize high findings |
| 40–59 | **D** | Poor security | Immediate action on critical/high |
| 0–39 | **F** | Critical risk | Emergency remediation needed |

---

## 📄 Reports Guide

### Report Location
```
websentinel_output/
├── websentinel_report.json    ← Machine-readable data
└── websentinel_report.pdf     ← Professional PDF
```

Custom location ke liye:
```bash
python3 main.py -u https://example.com -p balanced --output-dir /path/to/my/reports
```

---

### JSON Report Structure

```json
{
  "websentinel_report": {
    "version": "1.0.0",
    "target": "https://example.com",
    "scan_profile": "balanced",
    "scan_date": "2024-11-15T10:23:45",
    "total_endpoints": 124,
    "total_findings": 23,
    "security_score": 48,
    "security_grade": "D",
    
    "attack_surface_summary": {
      "total_endpoints": 124,
      "by_type": { "dynamic": 67, "api": 18, "auth": 8, "admin": 3, "static": 28 },
      "endpoints_with_params": 45,
      "total_forms": 12
    },
    
    "technology_fingerprint": {
      "server": "Apache/2.4.51",
      "cms": "WordPress",
      "frameworks": ["React", "jQuery"],
      "languages": ["PHP", "JavaScript"]
    },
    
    "risk_distribution": {
      "critical": 2, "high": 5, "medium": 9, "low": 7, "info": 0
    },
    
    "vulnerabilities": [
      {
        "type": "SQLInjection",
        "severity": "critical",
        "title": "SQL Injection in parameter 'id'",
        "url": "https://example.com/post?id=1",
        "parameter": "id",
        "description": "SQL injection via GET parameter...",
        "evidence": "Error: you have an error in your sql syntax",
        "confidence": 90,
        "confidence_label": "Confirmed",
        "cwe": "CWE-89",
        "cvss": 9.8,
        "exploitability": "Probable",
        "remediation": "Use parameterized queries..."
      }
    ]
  }
}
```

> JSON report automation ke liye use kar sakte ho — CI/CD pipeline mein integrate karo ya apne dashboard mein import karo.

---

### PDF Report Sections

PDF report professionally formatted hoti hai jisme yeh sections hote hain:

1. **Cover Page** — Target, score, grade, finding counts
2. **Executive Summary** — Non-technical overview for management
3. **Attack Surface Overview** — Endpoint types, parameters, forms
4. **Risk Distribution** — Pie chart + severity table
5. **Technology Fingerprint** — Detected tech stack
6. **Detailed Findings** — Har vulnerability ki full details
7. **Risk Matrix** — Sab findings ek table mein priority ke saath
8. **Remediation Guidance** — Har vulnerability type ke liye fix kaise karein

---

## 🔍 Vulnerability Coverage

### Complete Module List (35+ Checks)

#### 💉 Injection Attacks
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| SQL Injection | CWE-89 | Critical | URL params + form fields mein SQLi test |
| NoSQL Injection | CWE-943 | High | MongoDB/CouchDB operators test |
| Command Injection | CWE-78 | Critical | OS command injection patterns |
| LDAP Injection | CWE-90 | High | LDAP query manipulation |
| XML/XXE Injection | CWE-611 | Critical | External entity injection |

#### 🌐 Cross-Site Attacks
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| Reflected XSS | CWE-79 | High | URL params mein XSS reflection |
| Stored XSS | CWE-79 | Critical | Form submit ke baad persistent XSS |
| DOM-Based XSS | CWE-79 | Medium | Client-side DOM manipulation |
| CSRF | CWE-352 | Medium | Missing CSRF token detection |

#### 🔐 Access Control
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| IDOR | CWE-639 | High | Object ID manipulation test |
| Broken Auth | CWE-523 | High | HTTP login, autocomplete issues |
| Session Hijacking | CWE-598 | High | Session ID in URL detection |
| Session Fixation | CWE-384 | Medium | Cookie security flags |
| Broken Access Control | CWE-284 | High | Sensitive admin paths access |
| Privilege Escalation | CWE-269 | High | Mass assignment via forms |

#### 🌍 Network & Protocol
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| SSRF | CWE-918 | Critical | Server-side request forgery |
| Open Redirect | CWE-601 | Medium | URL redirect manipulation |
| CORS Misconfiguration | CWE-942 | High | Wildcard origin, credential issues |
| Host Header Injection | CWE-113 | High | Host header reflection |
| Cache Poisoning | CWE-444 | High | Response cache manipulation |
| Clickjacking | CWE-1021 | Medium | Missing frame protection |
| HTTP Response Splitting | CWE-113 | Medium | Header injection via newlines |

#### 📁 File & Path
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| LFI (Local File Inclusion) | CWE-22 | Critical | ../etc/passwd patterns |
| RFI (Remote File Inclusion) | CWE-98 | Critical | Remote file execute via include |
| Path Traversal | CWE-22 | Critical | Directory traversal sequences |
| File Upload | CWE-434 | Medium | Unrestricted file upload detection |
| Directory Listing | CWE-548 | Medium | Open directory exposure |

#### 🔎 Information Disclosure
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| Sensitive File Exposure | CWE-538 | Critical | .env, .git/config, wp-config.php |
| Server Info Disclosure | CWE-200 | Low | Version headers in responses |
| Hardcoded Credentials | CWE-798 | Critical | Passwords/keys in source code |
| Stack Trace Disclosure | CWE-200 | Medium | Error messages with internals |

#### 🔧 Security Configuration
| Module | CWE | Severity | Description |
|--------|-----|----------|-------------|
| Missing Security Headers | CWE-693 | Medium | HSTS, CSP, X-Frame-Options, etc. |
| Weak Cryptography | CWE-327 | Medium | MD5, SHA-1, HTTP usage |
| API Misconfiguration | CWE-200 | Medium | Debug endpoints, Swagger exposure |
| Rate Limiting Missing | CWE-307 | Medium | Brute-force vulnerable endpoints |
| Subdomain Takeover | CWE-285 | Critical | Unclaimed cloud service detection |
| Insecure Deserialization | CWE-502 | High | Serialization patterns |

---

## 🔄 Scan Stages Explained

Scan run karne par yeh 7 stages hote hain:

### Stage 1: Initializing Engines
- Request engine setup (session, headers, cookies)
- Rate limiter configure
- Diff engine initialize

### Stage 2: Technology Fingerprinting
- Server header analyze (`Apache/2.4`, `Nginx/1.21`, etc.)
- CMS detect (WordPress, Drupal, Joomla, Shopify)
- Frameworks detect (React, Vue, Django, Laravel)
- WAF detect (Cloudflare, ModSecurity, Akamai)
- Language detect (PHP, Python, Java, Ruby)

### Stage 3: Web Crawling
- robots.txt parse → disallowed paths discover
- sitemap.xml parse → all listed URLs queue mein
- BFS (Breadth-First Search) se pages visit
- Har page se: links extract, forms detect, params map

### Stage 4: Endpoint Classification
- Har endpoint ka type assign: `static`, `dynamic`, `api`, `auth`, `admin`
- Priority assign: `admin` (10) > `auth` (9) > `api` (8) > `dynamic` (6)
- Relevant modules decide: dynamic params wale endpoints ko injection test

### Stage 5: Vulnerability Scanning
- Priority order mein endpoints scan
- Har endpoint par relevant modules run
- Real-time progress bar show
- Findings collect

### Stage 6: Risk Scoring
- Har finding ka confidence-weighted score
- Critical findings = zyada deductions
- Final score: `100 - total_deductions`
- Grade assign: 90+=A, 75-89=B, 60-74=C, 40-59=D, 0-39=F

### Stage 7: Report Generation
- JSON report save
- PDF render (cover, charts, findings, remediation)
- Output folder mein copy

---

## 📁 Project Structure

```
websentinel_framework/
│
├── main.py                     # 🎯 Entry point — scan orchestration
├── config.py                   # ⚙️  All config, payloads, thresholds
├── requirements.txt            # 📦 Python dependencies
├── LICENSE                     # 📜 MIT License
├── README.md                   # 📖 This file
│
├── core/                       # 🔧 Core engines
│   ├── __init__.py
│   ├── crawler.py              # Spider — BFS web crawling + form detection
│   ├── request_engine.py       # HTTP engine — throttling, retries, sessions, cookie injection
│   ├── auth_handler.py         # ⭐ NEW — Form login, cookie session, CSRF capture, verification
│   ├── response_analyzer.py    # Response analysis — headers, cookies, patterns
│   ├── diff_engine.py          # Baseline vs probe comparison
│   └── scorer.py               # Risk scoring + grade calculation
│
├── modules/                    # 🔍 Vulnerability scanner modules
│   ├── __init__.py
│   ├── base_module.py          # Abstract base class for all modules
│   ├── injection_modules.py    # SQL, NoSQL, Cmd, LDAP, XML injection
│   ├── xss_modules.py          # Reflected, Stored, DOM XSS + CSRF
│   ├── access_modules.py       # IDOR, BrokenAuth, Session, BAC
│   ├── network_modules.py      # SSRF, OpenRedirect, CORS, Headers
│   ├── file_modules.py         # LFI, RFI, PathTraversal, Upload, Disclosure
│   └── misc_modules.py         # API, MassAssign, Crypto, Takeover, Cache
│
├── intelligence/               # 🧠 Analysis & classification
│   ├── __init__.py
│   ├── fingerprint.py          # Tech stack detection engine
│   ├── endpoint_classifier.py  # Endpoint type + module recommender
│   └── risk_matrix.py          # Risk matrix + remediation database
│
├── reports/                    # 📊 Report generators
│   ├── __init__.py
│   ├── json_report.py          # JSON structured report
│   └── pdf_report.py           # PDF report (ReportLab dark theme)
│
└── utils/                      # 🛠️  Utility functions
    ├── __init__.py
    ├── logger.py               # Colored terminal logger + ASCII banner
    └── helpers.py              # URL normalization, dedup, rate limiter
```

---

## ⚙️ Configuration Guide

`config.py` file mein sab kuch configure kar sakte ho:

### Rate Limiting Adjust karo
```python
# config.py mein change karo:
DEFAULT_DELAY = 1.0           # Seconds between requests
MAX_REQUESTS_PER_SECOND = 3   # Max RPS (command line se override hoga)
DEFAULT_TIMEOUT = 15          # Request timeout in seconds
```

### Custom Payloads Add karo
```python
# SQL injection ke naye payloads add karo
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' AND SLEEP(0)--",
    # Apna custom payload yahan add karo:
    "' OR SLEEP(0)--",
    "1 AND 1=1",
]
```

### Sensitive Files List Extend karo
```python
SENSITIVE_FILES = [
    "/.git/config",
    "/.env",
    "/wp-config.php",
    # Apni custom files add karo:
    "/application.properties",
    "/appsettings.json",
    "/.npmrc",
]
```

### Output Directory Change karo
```python
OUTPUT_DIR = "my_security_reports"    # Default output folder
JSON_REPORT_NAME = "scan_results.json"
PDF_REPORT_NAME = "security_report.pdf"
```

---

## 🔧 Troubleshooting

### Problem 1: `ModuleNotFoundError`
```bash
# Solution: Dependencies reinstall karo
pip install -r requirements.txt --upgrade

# Ya specific module:
pip install requests beautifulsoup4 colorama reportlab lxml
```

### Problem 2: SSL Certificate Errors
```bash
# Tool SSL warnings automatically suppress karta hai
# Agar phir bhi issue aaye:
pip install certifi --upgrade
```

### Problem 3: Target Unreachable / Connection Error
```bash
# Check karo website accessible hai
curl -I https://your-target.com

# Timeout increase karo
python3 main.py -u https://example.com -p passive --timeout 30
```

### Problem 4: PDF Generate Nahi Ho Raha
```bash
# ReportLab reinstall karo
pip install reportlab --upgrade

# Ya PDF skip karo, sirf JSON lao
python3 main.py -u https://example.com -p balanced --json-only
```

### Problem 5: WAF Block Kar Raha Hai (429/403 responses)
```bash
# Rate limit bahut kam karo
python3 main.py -u https://example.com -p passive --rps 0.25 --delay 5

# Passive profile use karo
python3 main.py -u https://example.com -p passive
```

### Problem 6: Bahut Slow Scan
```bash
# Depth kam karo
python3 main.py -u https://example.com -p balanced -d 2

# Deep-safe profile ki jagah balanced use karo
python3 main.py -u https://example.com -p balanced
```

### Problem 7: `Permission denied`
```bash
# Linux mein execute permission do
chmod +x main.py

# Ya directly python se run karo
python3 main.py -u https://example.com -p passive
```

---

## 💼 Use Cases

### Use Case 1: Freelance Web Developer
Apne client ko deliver karne se pehle website ki security check karo:
```bash
python3 main.py -u https://client-website.com -p balanced
# PDF report client ko forward karo as proof of security testing
```

### Use Case 2: Bug Bounty Hunter
HackerOne / Bugcrowd program mein participate karo:
```bash
# Recon phase
python3 main.py -u https://target.com -p passive --output-dir ./recon

# Active scan (sirf in-scope)
python3 main.py -u https://api.target.com -p balanced --output-dir ./active

# JSON se findings extract karo
cat websentinel_output/websentinel_report.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for v in data['websentinel_report']['vulnerabilities']:
    if v['severity'] in ('critical', 'high'):
        print(f\"{v['severity'].upper()}: {v['title']} — {v['url']}\")
"
```

### Use Case 3: Startup CTO / Security-Conscious Developer
Monthly security audit automate karo:
```bash
#!/bin/bash
# monthly_scan.sh
DATE=$(date +%Y%m%d)
python3 /path/to/main.py \
  -u https://myapp.com \
  -p balanced \
  --output-dir ./security_audits/$DATE \
  --json-only

echo "Scan complete: ./security_audits/$DATE"
```

### Use Case 4: Penetration Tester (Professional)
Client pentest ke liye:
```bash
# Phase 1: Passive recon
python3 main.py -u https://client.com -p passive --output-dir ./phase1_recon

# Phase 2: Authenticated scan
python3 main.py -u https://client.com -p deep-safe \
  --cookies "session=clientcookie; role=admin" \
  --output-dir ./phase2_auth_scan

# Phase 3: API specific
python3 main.py -u https://api.client.com -p deep-safe \
  --output-dir ./phase3_api

# Professional PDF report client ko deliver karo
```

### Use Case 5: Security Researcher / Student
CTF aur learning ke liye:
```bash
# Local lab environment (DVWA, WebGoat, etc.)
python3 main.py -u http://localhost/dvwa -p deep-safe \
  --cookies "PHPSESSID=abc; security=low" \
  --no-robots

# VulnHub / HackTheBox machine
python3 main.py -u http://10.10.10.50 -p deep-safe --no-robots
```

### Use Case 6: DevSecOps / CI-CD Integration
GitHub Actions ya Jenkins mein integrate karo:
```yaml
# .github/workflows/security-scan.yml
- name: WebSentinel Security Scan
  run: |
    pip install -r requirements.txt
    echo "yes" | python3 main.py \
      -u https://staging.myapp.com \
      -p balanced \
      --json-only \
      --rps 2
    
- name: Check for Critical Findings
  run: |
    python3 -c "
    import json, sys
    with open('websentinel_output/websentinel_report.json') as f:
        data = json.load(f)
    criticals = data['websentinel_report']['risk_distribution']['critical']
    if criticals > 0:
        print(f'FAIL: {criticals} critical vulnerabilities found!')
        sys.exit(1)
    print('PASS: No critical vulnerabilities')
    "
```

---

## ❓ FAQ

**Q: Kya `--cookies` ke liye CSRF token zaroori hai?**
> A: Nahi. `--cookies "session=abc123"` sirf session cookie se kaam karta hai — koi additional token required nahi. WebSentinel ne is issue ko v1.1.0 mein fix kar diya.

**Q: `--login` flag kaise kaam karta hai internally?**
> A: WebSentinel GET request karta hai login page par → HTML form parse karta hai → username/password fields auto-detect karta hai → CSRF token extract karta hai (agar hai) → POST request submit karta hai → redirect analyze karta hai → session cookies capture karta hai.

**Q: Login successful hua ya nahi, kaise pata chalega?**
> A: Terminal mein `[SUCCESS] ✔ Login successful!` dikhega. Agar nahi hua toh `[WARNING] Login may have failed` dikhega with reason. `--auth-verify` flag se extra confirmation milta hai.

**Q: Kya `--login` aur `--cookies` dono saath use kar sakte hain?**
> A: Haan! Login ke baad extra cookies inject karne ke liye dono combine karo. Example: `--login "user=x&pass=y" --cookies "remember_me=1"`

**Q: Login ke baad kaunsa URL scan hoga?**
> A: Default mein login URL ka base domain scan hoga (e.g., login URL `https://example.com/login` hai toh `https://example.com` scan hoga). `--scan-url` flag se custom URL specify kar sakte ho.

**Q: Kya yeh tool kisi bhi website pe use kar sakte hain?**
> A: Nahi. Sirf wahi websites jo aapki hain ya jahan aapko written permission mili ho. Unauthorized scanning illegal hai.

**Q: Kya yeh tool koi data delete karta hai?**
> A: Nahi. WebSentinel strictly non-destructive hai — sirf requests bhejta hai aur responses analyze karta hai. Koi data modify ya delete nahi hota.

**Q: WAF (Firewall) block kar raha hai, kya karein?**
> A: Passive profile use karo, RPS 0.5 se kam rakho, delay badha do. WAF bypass is tool ka scope nahi hai.

**Q: Kya yeh tool Burp Suite ki jagah use kar sakte hain?**
> A: Ye complementary tools hain. WebSentinel automated reconnaissance ke liye best hai; Burp Suite manual deep testing ke liye. Dono saath use karein.

**Q: Findings false positive toh nahi hain?**
> A: Har finding ka confidence score (0-100%) hota hai. 70%+ findings generally accurate hain. Verify karna hamesha recommended hai.

**Q: Python 2 mein kaam karega?**
> A: Nahi. Python 3.8+ required hai.

**Q: Kya yeh HTTPS ke saath kaam karta hai?**
> A: Haan. SSL certificate verify karna off hai (self-signed certs ke liye) but HTTPS fully supported hai.

**Q: Report kahan save hoti hai?**
> A: Default: `./websentinel_output/` folder mein. `--output-dir` flag se change kar sakte ho.

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `requests` | ≥2.31.0 | HTTP requests engine |
| `beautifulsoup4` | ≥4.12.0 | HTML parsing for crawler |
| `colorama` | ≥0.4.6 | Cross-platform colored terminal |
| `reportlab` | ≥4.0.4 | Professional PDF generation |
| `lxml` | ≥4.9.0 | Fast XML/HTML parser |
| `urllib3` | ≥2.0.0 | HTTP connection pooling |

---

## 📜 License

MIT License — See [LICENSE](LICENSE) file for full text.

**Short version**: Aap freely use, modify, distribute kar sakte ho — sirf copyright notice rakho aur authorized testing ke liye use karo.

---

## ⚠️ Final Warning

```
╔══════════════════════════════════════════════════════════════╗
║                    RESPONSIBLE USE ONLY                     ║
║                                                              ║
║  ✅ Apni website test karo                                  ║
║  ✅ Bug bounty (in-scope) targets                            ║
║  ✅ Written permission ke saath client systems               ║
║  ✅ Local lab environments (DVWA, WebGoat, etc.)            ║
║                                                              ║
║  ❌ Kisi ki bhi website bina permission ke mat scan karo    ║
║  ❌ Production systems par deep-safe profile se bachein     ║
║  ❌ Malicious purpose ke liye use mat karo                  ║
╚══════════════════════════════════════════════════════════════╝
```

---

<div align="center">

**⚡ WebSentinel Framework** — Built for ethical security professionals

*"Scan responsibly. Disclose responsibly. Fix responsibly."*

</div>
