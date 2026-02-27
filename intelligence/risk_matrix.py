"""
WebSentinel Framework - Risk Matrix
Generates risk matrix and remediation guidance for findings.
"""

from typing import List, Dict
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.scorer import Finding


REMEDIATION_DB: Dict[str, str] = {
    "SQLInjection": (
        "Use parameterized queries / prepared statements. Never concatenate user input into SQL. "
        "Apply an ORM. Use Web Application Firewall. Implement least-privilege DB accounts."
    ),
    "NoSQLInjection": (
        "Validate and sanitize all input before passing to NoSQL queries. "
        "Avoid operators like $where. Use schema validation."
    ),
    "XSS": (
        "Encode all output using context-aware escaping (HTML, JS, CSS, URL contexts). "
        "Implement a strict Content-Security-Policy. Use HttpOnly and Secure cookie flags."
    ),
    "CSRF": (
        "Implement CSRF tokens (synchronizer token pattern). Use SameSite=Strict cookie attribute. "
        "Validate Origin and Referer headers for state-changing operations."
    ),
    "SSRF": (
        "Whitelist allowed outbound destinations. Disable unnecessary URL schemes (file://, gopher://). "
        "Use network-level controls to block access to internal services."
    ),
    "OpenRedirect": (
        "Whitelist allowed redirect destinations. Avoid using user-controlled input for redirects. "
        "Use indirect mapping (e.g., numeric IDs) instead of raw URLs."
    ),
    "LFI": (
        "Never use user input directly in file path operations. Use whitelists for allowed files. "
        "Chroot / jail the application. Apply strict file permission controls."
    ),
    "PathTraversal": (
        "Canonicalize file paths before use. Reject paths containing '../'. "
        "Use allowlist-based file access rather than dynamic paths."
    ),
    "CommandInjection": (
        "Avoid calling OS commands from application code where possible. "
        "If necessary, use safe APIs with argument arrays. Strictly whitelist allowed commands."
    ),
    "SecurityHeaders": (
        "Add recommended security headers: Strict-Transport-Security, Content-Security-Policy, "
        "X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy."
    ),
    "CORS": (
        "Define an explicit allowlist of trusted origins. Never reflect the Origin header without validation. "
        "Do not combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
    ),
    "Clickjacking": (
        "Set X-Frame-Options: DENY or SAMEORIGIN. "
        "Alternatively, use CSP frame-ancestors directive."
    ),
    "InfoDisclosure": (
        "Suppress server version information. Remove debug endpoints. "
        "Configure error pages to return generic messages. Remove sensitive files from web root."
    ),
    "CookieSecurity": (
        "Set HttpOnly flag on all session cookies. Set Secure flag if HTTPS is used. "
        "Set SameSite=Strict or SameSite=Lax."
    ),
    "BrokenAuth": (
        "Enforce strong password policies. Implement MFA. Use secure session management. "
        "Rate-limit authentication endpoints."
    ),
    "IDOR": (
        "Implement proper authorization checks on every request. "
        "Use indirect object references (e.g., GUIDs). Log access attempts."
    ),
    "FileUpload": (
        "Validate file type by content (magic bytes), not just extension. "
        "Store uploads outside web root. Generate random filenames. "
        "Scan uploaded files with AV. Disable execution in upload directories."
    ),
    "APIMisconfiguration": (
        "Enable authentication on all API endpoints. Implement rate limiting. "
        "Use HTTPS only. Apply input validation. Disable debug/test endpoints in production."
    ),
    "RateLimiting": (
        "Implement rate limiting on sensitive endpoints (login, registration, password reset). "
        "Use CAPTCHA for brute-force-prone endpoints. Block after N failed attempts."
    ),
    "BrokenAccessControl": (
        "Enforce server-side authorization checks. Deny by default. "
        "Log and monitor access control failures."
    ),
    "SubdomainTakeover": (
        "Audit DNS records regularly. Remove CNAME records pointing to deprovisioned services. "
        "Claim or remove unused cloud service subdomains."
    ),
    "HostHeaderInjection": (
        "Validate the Host header against a whitelist of allowed values. "
        "Avoid using the Host header in email generation or redirects."
    ),
    "CachePoisoning": (
        "Set appropriate Cache-Control headers. Do not cache responses with user-supplied data. "
        "Use cache keys that include all differentiating headers."
    ),
    "WeakCrypto": (
        "Use TLS 1.2+ with strong cipher suites. Disable MD5, SHA-1, RC4, DES. "
        "Use bcrypt, scrypt, or Argon2 for password hashing."
    ),
}


class RiskMatrix:
    """Builds a risk matrix from findings with remediation guidance."""

    def build(self, findings: List[Finding]) -> List[Dict]:
        """Create full risk matrix entries."""
        matrix = []
        for f in findings:
            remediation = REMEDIATION_DB.get(f.vuln_type, f.remediation or "Consult OWASP guidelines.")
            matrix.append({
                "title": f.title,
                "type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "exploitability": f.exploitability,
                "url": f.url,
                "parameter": f.parameter,
                "description": f.description,
                "evidence": f.evidence,
                "cwe": f.cwe,
                "cvss": f.cvss,
                "remediation": remediation,
            })
        return matrix

    def get_remediation(self, vuln_type: str) -> str:
        """Get remediation guidance for a vulnerability type."""
        return REMEDIATION_DB.get(vuln_type, "Consult OWASP guidelines for this vulnerability type.")
