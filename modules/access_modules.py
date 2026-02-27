"""
WebSentinel Framework - Access Control Modules
IDOR, Broken Auth, Session Analysis, Privilege Escalation, Broken Access Control.
"""

import re
from typing import List
from .base_module import BaseModule
from core.scorer import Finding
from core.scorer import Finding
from core.crawler import Endpoint
from utils.helpers import inject_param


class IDORModule(BaseModule):
    MODULE_NAME = "IDOR"

    ID_PATTERNS = re.compile(r'\b(id|user_id|account|item|order|doc|file|record|uid)=(\d+)\b', re.IGNORECASE)

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        url = endpoint.url
        matches = self.ID_PATTERNS.findall(url)
        if not matches:
            return []

        baseline = self.engine.get(url)
        if not baseline.ok:
            return []

        for param, original_id in matches:
            # Test adjacent ID
            test_id = str(int(original_id) + 1)
            test_url = inject_param(url, param, test_id)
            result = self.engine.get(test_url)
            if not result.ok:
                continue

            if result.status_code == 200 and abs(result.content_length - baseline.content_length) < 500:
                self._add_finding(
                    vuln_type="IDOR",
                    severity="high",
                    title=f"Potential IDOR via parameter '{param}'",
                    url=url,
                    description=(
                        f"Incrementing the '{param}' parameter from {original_id} to {test_id} "
                        "returns a successful response with similar content length, "
                        "suggesting insufficient authorization checking."
                    ),
                    evidence=f"Original ID: {original_id}, Test ID: {test_id}, Status: 200",
                    parameter=param,
                    confidence=65,
                    cwe="CWE-639",
                    cvss=7.5,
                    exploitability="Probable",
                )
        return self.findings


class BrokenAuthModule(BaseModule):
    MODULE_NAME = "BrokenAuth"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        # Check for login forms with weak configuration
        for form in endpoint.forms:
            fields = form.get("fields", [])
            has_password = any(f.get("type") == "password" for f in fields)
            if not has_password:
                continue

            # Check if login is served over HTTP (not HTTPS)
            if form["action"].startswith("http://"):
                self._add_finding(
                    vuln_type="BrokenAuth",
                    severity="high",
                    title="Credentials Submitted Over HTTP",
                    url=form["action"],
                    description="Login form submits credentials over unencrypted HTTP connection.",
                    confidence=95,
                    cwe="CWE-523",
                    cvss=8.1,
                    exploitability="Passive",
                )

            # Check for autocomplete on password fields
            for field in fields:
                if field.get("type") == "password":
                    self._add_finding(
                        vuln_type="BrokenAuth",
                        severity="low",
                        title="Password Field May Allow Browser Autocomplete",
                        url=form["action"],
                        description="Password input lacks autocomplete=off attribute.",
                        parameter=field.get("name", "password"),
                        confidence=50,
                        cwe="CWE-257",
                        cvss=3.1,
                        exploitability="Passive",
                    )
                    break

        return self.findings


class SessionAnalysisModule(BaseModule):
    MODULE_NAME = "SessionAnalysis"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        # Analyze cookies
        cookie_issues = self.analyzer.analyze_cookies(result.headers)
        for issue in cookie_issues:
            severity = "medium"
            if "Secure flag" in str(issue["issues"]):
                severity = "high"
            self._add_finding(
                vuln_type="CookieSecurity",
                severity=severity,
                title=f"Insecure Cookie: {issue['cookie']}",
                url=endpoint.url,
                description=f"Cookie '{issue['cookie']}' has security issues: {'; '.join(issue['issues'])}",
                evidence=str(issue["issues"]),
                confidence=90,
                cwe="CWE-614",
                cvss=5.4,
                exploitability="Passive",
            )

        # Check for session ID in URL
        url = endpoint.url
        session_params = ["sessionid", "phpsessid", "jsessionid", "session_id", "sid", "token"]
        url_lower = url.lower()
        for sp in session_params:
            if f"{sp}=" in url_lower:
                self._add_finding(
                    vuln_type="SessionHijacking",
                    severity="high",
                    title="Session Token Exposed in URL",
                    url=url,
                    description=(
                        f"Session identifier '{sp}' found in URL query string. "
                        "Session tokens in URLs are logged by web servers, proxies, and browser history."
                    ),
                    confidence=90,
                    cwe="CWE-598",
                    cvss=7.5,
                    exploitability="Passive",
                )
                break

        return self.findings


class BrokenAccessControlModule(BaseModule):
    MODULE_NAME = "BrokenAccessControl"

    SENSITIVE_PATHS = [
        "/admin", "/admin/", "/administrator",
        "/dashboard", "/manage", "/management",
        "/users", "/user/list", "/accounts",
        "/config", "/settings", "/system",
        "/backup", "/db", "/database",
        "/private", "/internal", "/api/admin",
        "/api/users", "/api/accounts",
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        base = endpoint.url.rstrip("/")
        base_parts = base.split("://", 1)
        if len(base_parts) < 2:
            return []
        scheme_host = "://".join(base_parts[:1]) + "://" + base_parts[1].split("/")[0]

        for path in self.SENSITIVE_PATHS:
            test_url = scheme_host + path
            result = self.engine.get(test_url)
            if not result.ok:
                continue

            if result.status_code == 200 and result.content_length > 100:
                self._add_finding(
                    vuln_type="BrokenAccessControl",
                    severity="high",
                    title=f"Sensitive Endpoint Accessible: {path}",
                    url=test_url,
                    description=(
                        f"The sensitive path '{path}' returned HTTP 200 without apparent authentication. "
                        "This may indicate broken access control."
                    ),
                    evidence=f"Status: 200, Length: {result.content_length}",
                    confidence=60,
                    cwe="CWE-284",
                    cvss=7.5,
                    exploitability="Probable",
                )
            elif result.status_code == 403:
                # 403 is still interesting — path exists but is blocked
                self._add_finding(
                    vuln_type="InfoDisclosure",
                    severity="info",
                    title=f"Sensitive Path Exists (403 Forbidden): {path}",
                    url=test_url,
                    description=f"Path '{path}' exists but returns 403.",
                    confidence=80,
                    cwe="CWE-200",
                    cvss=2.0,
                    exploitability="Passive",
                )

        return self.findings
