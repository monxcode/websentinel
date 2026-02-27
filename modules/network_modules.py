"""
WebSentinel Framework - Network & Protocol Modules
SSRF, Open Redirect, CORS, Host Header Injection, Clickjacking,
Security Headers, Directory Listing, Rate Limiting, HTTP Response Splitting.
"""

import re
from typing import List
from .base_module import BaseModule
from core.scorer import Finding
from core.crawler import Endpoint
from utils.helpers import inject_param
import config


class SSRFModule(BaseModule):
    MODULE_NAME = "SSRF"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        # Focus on params likely to accept URLs
        url_params = [p for p in endpoint.params if any(
            k in p.lower() for k in ["url", "uri", "link", "src", "dest", "redirect",
                                      "path", "resource", "target", "host", "fetch"]
        )]
        if not url_params:
            url_params = list(endpoint.params.keys())[:2]  # test first 2 params

        for param in url_params:
            for payload in config.SSRF_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue

                ssrf_hits = self.analyzer.detect_ssrf_patterns(result.body)
                if ssrf_hits:
                    self._add_finding(
                        vuln_type="SSRF",
                        severity="critical",
                        title=f"Server-Side Request Forgery (SSRF) in '{param}'",
                        url=endpoint.url,
                        description=(
                            f"SSRF vulnerability detected. The parameter '{param}' "
                            f"causes the server to make internal requests. "
                            f"Payload: {payload}"
                        ),
                        evidence=f"Response patterns: {', '.join(ssrf_hits)}",
                        parameter=param,
                        confidence=88,
                        cwe="CWE-918",
                        cvss=9.3,
                        exploitability="Probable",
                    )
                    break

                # Status anomaly may also indicate SSRF
                diff = self.diff.compare_results(
                    self.engine.get(endpoint.url), result
                )
                if diff.status_changed and result.status_code in (200, 301, 302):
                    self._add_finding(
                        vuln_type="SSRF",
                        severity="medium",
                        title=f"Potential SSRF in parameter '{param}'",
                        url=endpoint.url,
                        description=f"Parameter '{param}' may accept URLs and trigger server-side requests",
                        parameter=param,
                        confidence=50,
                        cwe="CWE-918",
                        cvss=6.5,
                        exploitability="Passive",
                    )
                    break
        return self.findings


class OpenRedirectModule(BaseModule):
    MODULE_NAME = "OpenRedirect"

    REDIRECT_PARAMS = [
        "redirect", "redirect_uri", "redirect_url", "next", "return",
        "returnto", "return_url", "goto", "url", "destination",
        "dest", "target", "continue", "successurl",
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject():
            return []

        # Only test known redirect parameters
        redirect_params = [p for p in endpoint.params if p.lower() in self.REDIRECT_PARAMS]
        if not redirect_params and endpoint.params:
            redirect_params = [p for p in endpoint.params if any(
                k in p.lower() for k in ["redirect", "url", "next", "return", "goto"]
            )]

        for param in redirect_params:
            for payload in config.OPEN_REDIRECT_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url, allow_redirects=False)
                if not result.ok:
                    continue

                if self.analyzer.detect_open_redirect(result, payload):
                    self._add_finding(
                        vuln_type="OpenRedirect",
                        severity="medium",
                        title=f"Open Redirect via parameter '{param}'",
                        url=endpoint.url,
                        description=(
                            f"The '{param}' parameter redirects to arbitrary URLs. "
                            f"Exploitable for phishing. Payload: {payload}"
                        ),
                        evidence=f"Location: {result.headers.get('Location', payload)}",
                        parameter=param,
                        confidence=85,
                        cwe="CWE-601",
                        cvss=6.1,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class CORSModule(BaseModule):
    MODULE_NAME = "CORS"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        for test_origin in config.CORS_MISCONFIG_ORIGINS:
            result = self.engine.get(
                endpoint.url,
                extra_headers={"Origin": test_origin},
            )
            if not result.ok:
                continue

            finding = self.analyzer.analyze_cors(result.headers, test_origin)
            if finding:
                self._add_finding(
                    vuln_type="CORS",
                    severity=finding.get("severity", "medium"),
                    title=f"CORS Misconfiguration: {finding.get('issue', '')[:60]}",
                    url=endpoint.url,
                    description=f"CORS issue: {finding.get('issue')}",
                    evidence=(
                        f"Origin: {test_origin} | "
                        f"Access-Control-Allow-Origin: {finding.get('allow_origin')} | "
                        f"Access-Control-Allow-Credentials: {finding.get('allow_credentials', 'N/A')}"
                    ),
                    confidence=90,
                    cwe="CWE-942",
                    cvss=7.5,
                    exploitability="Probable",
                )
                break
        return self.findings


class SecurityHeadersModule(BaseModule):
    MODULE_NAME = "SecurityHeaders"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        analysis = self.analyzer.analyze_security_headers(result.headers)

        for missing in analysis["missing"]:
            severity = "medium"
            cvss = 5.3
            if missing in ("Strict-Transport-Security", "Content-Security-Policy"):
                severity = "medium"
            elif missing == "X-Frame-Options":
                severity = "medium"
            else:
                severity = "low"
                cvss = 3.1

            self._add_finding(
                vuln_type="SecurityHeaders",
                severity=severity,
                title=f"Missing Security Header: {missing}",
                url=endpoint.url,
                description=f"The HTTP response is missing the '{missing}' security header.",
                confidence=98,
                cwe="CWE-693",
                cvss=cvss,
                exploitability="Passive",
            )

        for msg in analysis.get("misconfigured", []):
            self._add_finding(
                vuln_type="SecurityHeaders",
                severity="low",
                title=f"Misconfigured Security Header",
                url=endpoint.url,
                description=msg,
                confidence=90,
                cwe="CWE-693",
                cvss=3.1,
                exploitability="Passive",
            )

        return self.findings


class ClickjackingModule(BaseModule):
    MODULE_NAME = "Clickjacking"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        # Only flag HTML pages
        ct = result.headers.get("Content-Type", "")
        if "html" not in ct.lower() and ct:
            return []

        finding = self.analyzer.check_clickjacking(result.headers)
        if finding:
            self._add_finding(
                vuln_type="Clickjacking",
                severity=finding["severity"],
                title="Page Vulnerable to Clickjacking",
                url=endpoint.url,
                description=finding["issue"],
                confidence=88,
                cwe="CWE-1021",
                cvss=4.3,
                exploitability="Passive",
            )
        return self.findings


class DirectoryListingModule(BaseModule):
    MODULE_NAME = "DirectoryListing"

    DIRECTORY_INDICATORS = [
        "index of /", "parent directory",
        "<title>index of", "directory listing",
        "[dir]", "[file]",
    ]
    TEST_PATHS = [
        "/uploads/", "/images/", "/files/", "/assets/",
        "/backup/", "/static/", "/media/", "/docs/",
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        # Test main endpoint
        result = self.engine.get(endpoint.url)
        if result.ok:
            body_lower = result.body.lower()
            if any(ind in body_lower for ind in self.DIRECTORY_INDICATORS):
                self._add_finding(
                    vuln_type="DirectoryListing",
                    severity="medium",
                    title="Directory Listing Enabled",
                    url=endpoint.url,
                    description="Directory listing is enabled, exposing file system structure.",
                    confidence=92,
                    cwe="CWE-548",
                    cvss=5.3,
                    exploitability="Passive",
                )

        return self.findings


class HostHeaderInjectionModule(BaseModule):
    MODULE_NAME = "HostHeaderInjection"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        # Only test root-level paths
        from urllib.parse import urlparse
        parsed = urlparse(endpoint.url)
        if parsed.path not in ("", "/"):
            return []

        inject_host = "evil.com"
        result = self.engine.get(
            endpoint.url,
            extra_headers={"Host": inject_host},
        )
        if not result.ok:
            return []

        if inject_host in result.body or inject_host in result.headers.get("Location", ""):
            self._add_finding(
                vuln_type="HostHeaderInjection",
                severity="high",
                title="Host Header Injection",
                url=endpoint.url,
                description=(
                    "The application reflects the injected Host header value in the response. "
                    "This can be exploited for password reset poisoning, web cache poisoning, and SSRF."
                ),
                evidence=f"Injected Host 'evil.com' reflected in response",
                confidence=82,
                cwe="CWE-113",
                cvss=7.5,
                exploitability="Probable",
            )
        return self.findings


class RateLimitingModule(BaseModule):
    MODULE_NAME = "RateLimiting"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        # Only test auth endpoints
        if endpoint.endpoint_type not in ("auth",):
            return []

        # Send 5 quick requests and check for rate limiting headers
        statuses = []
        for _ in range(5):
            r = self.engine.get(endpoint.url)
            if r.ok:
                statuses.append(r.status_code)

        has_rate_limit = any(
            h.lower() in ("x-ratelimit-limit", "x-rate-limit", "retry-after", "x-ratelimit-remaining")
            for h in (list(endpoint.params.keys()) if endpoint.params else [])
        )

        if statuses and len(set(statuses)) == 1 and statuses[0] == 200:
            if not has_rate_limit:
                self._add_finding(
                    vuln_type="RateLimiting",
                    severity="medium",
                    title="No Rate Limiting Detected on Authentication Endpoint",
                    url=endpoint.url,
                    description=(
                        "The authentication endpoint does not appear to implement rate limiting. "
                        "This may allow brute-force attacks."
                    ),
                    evidence="5 consecutive requests returned HTTP 200 without throttling",
                    confidence=60,
                    cwe="CWE-307",
                    cvss=6.5,
                    exploitability="Passive",
                )
        return self.findings
