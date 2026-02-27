"""
WebSentinel Framework - Configuration Module
Central configuration for all scan parameters and defaults.
"""

# ─────────────────────────────────────────────
# VERSION & IDENTITY
# ─────────────────────────────────────────────
VERSION = "1.0.0"
TOOL_NAME = "WebSentinel Framework"
AUTHOR = "WebSentinel Security"

# ─────────────────────────────────────────────
# SCAN PROFILES
# ─────────────────────────────────────────────
SCAN_PROFILES = {
    "passive": {
        "description": "Passive reconnaissance only. No active probing.",
        "max_depth": 2,
        "delay_range": (1.5, 3.0),
        "max_rps": 1,
        "active_probing": False,
        "injection_tests": False,
        "fuzz_params": False,
    },
    "balanced": {
        "description": "Balanced scan with light active analysis.",
        "max_depth": 3,
        "delay_range": (0.8, 2.0),
        "max_rps": 3,
        "active_probing": True,
        "injection_tests": True,
        "fuzz_params": False,
    },
    "deep-safe": {
        "description": "Deep safe scan with comprehensive non-destructive analysis.",
        "max_depth": 5,
        "delay_range": (0.5, 1.5),
        "max_rps": 5,
        "active_probing": True,
        "injection_tests": True,
        "fuzz_params": True,
    },
}

# ─────────────────────────────────────────────
# REQUEST ENGINE DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 2
DEFAULT_DELAY = 1.0
MAX_REQUESTS_PER_SECOND = 3
USER_AGENT = (
    f"Mozilla/5.0 (compatible; WebSentinel/1.0.0; "
    "Security Assessment; +https://example.com/websentinel)"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# ─────────────────────────────────────────────
# CRAWLER DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_CRAWL_DEPTH = 3
MAX_ENDPOINTS_PER_SCAN = 500
STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
    ".zip", ".tar", ".gz", ".mp4", ".mp3", ".avi",
}
API_PATH_PATTERNS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/ws/",
    "/webhook", "/service/", "/rpc",
]
AUTH_PATH_PATTERNS = [
    "/login", "/logout", "/signin", "/signup", "/register",
    "/auth/", "/oauth/", "/token", "/session", "/password",
    "/forgot", "/reset", "/verify", "/2fa", "/mfa",
]
ADMIN_PATH_PATTERNS = [
    "/admin", "/administrator", "/dashboard", "/manage", "/management",
    "/control", "/panel", "/cp/", "/backend", "/cms", "/staff",
    "/superuser", "/root", "/wp-admin", "/phpmyadmin",
]

# ─────────────────────────────────────────────
# VULNERABILITY PAYLOADS
# ─────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
    "' AND SLEEP(0)--", "1; SELECT 1--", "' UNION SELECT NULL--",
    "admin'--", "' OR 'x'='x",
]
SQLI_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error", "microsoft ole db provider for sql server",
    "ora-", "pg_query()", "sqlite3.operationalerror",
    "sqlstate", "mysql_fetch",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}',
    '[$ne]=1', '[$gt]=', '{"$regex": ".*"}',
]

CMD_INJECTION_PAYLOADS = [
    ";ls", "|ls", "&&ls", ";id", "|id", "&&id",
    ";echo WebSentinel", "|echo WebSentinel", ";sleep 0",
]
CMD_INJECTION_PATTERNS = [
    "uid=", "gid=", "root:", "www-data", "websentinel",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]", "http://0.0.0.0",
]
SSRF_PATTERNS = ["root:x:", "ami-id", "instance-id", "metadata"]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com", "///evil.com",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
LFI_PATTERNS = ["root:x:", "[extensions]", "daemon:", "bin/bash"]

SENSITIVE_FILES = [
    "/.git/config", "/.env", "/config.php", "/wp-config.php",
    "/.htaccess", "/web.config", "/phpinfo.php", "/info.php",
    "/debug.log", "/error.log", "/access.log",
    "/backup.zip", "/backup.sql", "/dump.sql",
    "/.bash_history", "/.ssh/id_rsa",
    "/admin.php", "/test.php",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
]

CORS_MISCONFIG_ORIGINS = [
    "https://evil.com", "null", "https://attacker.com",
]

# ─────────────────────────────────────────────
# TECHNOLOGY FINGERPRINTS
# ─────────────────────────────────────────────
CMS_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-json", "WordPress"],
    "Drupal": ["/sites/default/", "Drupal.settings", "X-Generator: Drupal"],
    "Joomla": ["/components/com_", "Joomla!"],
    "Magento": ["/skin/frontend/", "Mage.Cookies"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Ghost": ["/ghost/", "Ghost CMS"],
    "Strapi": ["/strapi/", "X-Powered-By: Strapi"],
}
FRAMEWORK_SIGNATURES = {
    "React": ["__react", "_reactRootContainer", "react.development.js"],
    "Vue.js": ["__vue__", "vue.runtime", "data-v-"],
    "Angular": ["ng-version", "angular.min.js", "ng-app"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Rails": ["_rails_", "csrf-token", "data-remote"],
    "Express.js": ["X-Powered-By: Express"],
    "Flask": ["Werkzeug", "flask"],
    "ASP.NET": ["ASP.NET_SessionId", "X-AspNet-Version", "__VIEWSTATE"],
    "Spring": ["JSESSIONID", "X-Application-Context"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
}
SERVER_SIGNATURES = {
    "Apache": ["Apache", "mod_"],
    "Nginx": ["nginx", "Nginx"],
    "IIS": ["IIS", "Microsoft-IIS"],
    "Tomcat": ["Apache-Coyote", "Tomcat"],
    "Gunicorn": ["gunicorn"],
    "Caddy": ["Caddy"],
    "LiteSpeed": ["LiteSpeed"],
}

# ─────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}
GRADE_THRESHOLDS = {
    "A": (90, 100),
    "B": (75, 89),
    "C": (60, 74),
    "D": (40, 59),
    "F": (0, 39),
}

# ─────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────
OUTPUT_DIR = "websentinel_output"
JSON_REPORT_NAME = "websentinel_report.json"
PDF_REPORT_NAME = "websentinel_report.pdf"

LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                          LEGAL DISCLAIMER & WARNING                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  WebSentinel Framework is designed for AUTHORIZED security testing only.   ║
║                                                                              ║
║  By proceeding, you confirm that:                                           ║
║  1. You have EXPLICIT written authorization to test the target system.      ║
║  2. You are the system owner or have permission from the system owner.      ║
║  3. You understand that unauthorized scanning may be ILLEGAL.               ║
║  4. You accept full responsibility for your use of this tool.              ║
║  5. The tool authors bear NO liability for misuse.                         ║
║                                                                              ║
║  Unauthorized scanning violates computer crime laws including:              ║
║  - Computer Fraud and Abuse Act (CFAA) - United States                     ║
║  - Computer Misuse Act - United Kingdom                                     ║
║  - Similar laws in your jurisdiction                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
