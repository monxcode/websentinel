"""
WebSentinel Framework - Miscellaneous Modules
API Misconfiguration, Mass Assignment, Hardcoded Credentials,
Weak Cryptography, Subdomain Takeover, Cache Poisoning,
Insecure Deserialization, HTTP Response Splitting.
"""

import re
from typing import List
from .base_module import BaseModule
from core.scorer import Finding
from core.crawler import Endpoint
from utils.helpers import inject_param


class APIMisconfigModule(BaseModule):
    MODULE_NAME = "APIMisconfiguration"

    DEBUG_PATHS = ["/debug", "/health", "/metrics", "/status", "/actuator",
                   "/actuator/env", "/actuator/beans", "/swagger", "/swagger-ui",
                   "/swagger-ui.html", "/api-docs", "/openapi.json", "/v1/docs",
                   "/.well-known/security.txt", "/graphql", "/graphiql"]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing() or endpoint.endpoint_type != "api":
            return []

        from urllib.parse import urlparse
        parsed = urlparse(endpoint.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.DEBUG_PATHS:
            test_url = base + path
            result = self.engine.get(test_url)
            if not result.ok or result.status_code != 200:
                continue
            if result.content_length < 50:
                continue
            ct = result.headers.get("Content-Type", "")
            is_api = "json" in ct or "xml" in ct or result.content_length > 100

            if is_api:
                self._add_finding(
                    vuln_type="APIMisconfiguration",
                    severity="medium",
                    title=f"API Debug/Info Endpoint Exposed: {path}",
                    url=test_url,
                    description=(
                        f"API management or debug endpoint '{path}' is publicly accessible. "
                        "These endpoints may expose configuration, tokens, or internal state."
                    ),
                    evidence=f"Status: 200, Size: {result.content_length}",
                    confidence=82,
                    cwe="CWE-200",
                    cvss=5.3,
                    exploitability="Passive",
                )
        return self.findings


class MassAssignmentModule(BaseModule):
    MODULE_NAME = "MassAssignment"

    PRIVILEGE_PARAMS = ["role", "is_admin", "admin", "privilege", "group",
                        "permission", "is_superuser", "is_staff", "user_type"]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject():
            return []

        for form in endpoint.forms:
            if form["method"] != "POST":
                continue
            fields = form.get("fields", [])
            field_names = [f["name"].lower() for f in fields]

            # Try submitting with extra privilege-escalating parameters
            test_data = {f["name"]: "test" for f in fields}
            for priv_param in self.PRIVILEGE_PARAMS:
                test_data[priv_param] = "1"

            baseline = self.engine.post(form["action"], data={f["name"]: "test" for f in fields})
            result = self.engine.post(form["action"], data=test_data)

            if not baseline.ok or not result.ok:
                continue

            diff = self.diff.compare_results(baseline, result)
            if diff.is_anomalous:
                self._add_finding(
                    vuln_type="MassAssignment",
                    severity="high",
                    title=f"Potential Mass Assignment Vulnerability",
                    url=form["action"],
                    description=(
                        "The application may accept unexpected mass-assignment parameters. "
                        "Adding privilege-escalating fields caused a response difference."
                    ),
                    evidence="; ".join(diff.indicators[:2]),
                    confidence=55,
                    cwe="CWE-915",
                    cvss=8.1,
                    exploitability="Probable",
                )
        return self.findings


class HardcodedCredentialsModule(BaseModule):
    MODULE_NAME = "HardcodedCredentials"

    PATTERNS = [
        (r'password\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password in source"),
        (r'api[_-]?key\s*=\s*["\'][A-Za-z0-9+/]{16,}["\']', "Hardcoded API key"),
        (r'secret[_-]?key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret key"),
        (r'access[_-]?token\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded access token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}', "GitHub token"),
        (r'sk-[A-Za-z0-9]{32,}', "OpenAI API key"),
        (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "Private key material"),
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        for pattern, label in self.PATTERNS:
            matches = re.findall(pattern, result.body, re.IGNORECASE)
            if matches:
                self._add_finding(
                    vuln_type="HardcodedCredentials",
                    severity="critical",
                    title=f"Hardcoded Credentials Detected: {label}",
                    url=endpoint.url,
                    description=f"{label} found in page source code or response body.",
                    evidence=str(matches[0])[:80],
                    confidence=85,
                    cwe="CWE-798",
                    cvss=9.8,
                    exploitability="Passive",
                )
        return self.findings


class WeakCryptoModule(BaseModule):
    MODULE_NAME = "WeakCryptography"

    WEAK_PATTERNS = [
        (r'\bmd5\b|\bmd5sum\b', "MD5 usage detected"),
        (r'\bsha1\b|\bsha-1\b', "SHA-1 usage detected"),
        (r'\brc4\b', "RC4 cipher detected"),
        (r'\bdes\b(?!cription)', "DES cipher detected"),
        (r'http://', "Insecure HTTP usage"),
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        # Check HTTPS
        if endpoint.url.startswith("http://"):
            self._add_finding(
                vuln_type="WeakCrypto",
                severity="high",
                title="Site Not Using HTTPS",
                url=endpoint.url,
                description="The site is served over HTTP instead of HTTPS, exposing data in transit.",
                confidence=99,
                cwe="CWE-319",
                cvss=7.5,
                exploitability="Passive",
            )

        for pattern, label in self.WEAK_PATTERNS:
            if re.search(pattern, result.body, re.IGNORECASE):
                self._add_finding(
                    vuln_type="WeakCrypto",
                    severity="medium",
                    title=f"Weak Cryptography Reference: {label}",
                    url=endpoint.url,
                    description=f"{label} in page source. May indicate use of deprecated cryptographic functions.",
                    confidence=55,
                    cwe="CWE-327",
                    cvss=5.3,
                    exploitability="Passive",
                )
        return self.findings


class SubdomainTakeoverModule(BaseModule):
    MODULE_NAME = "SubdomainTakeover"

    TAKEOVER_INDICATORS = [
        ("There isn't a GitHub Pages site here", "GitHub Pages"),
        ("NoSuchBucket", "AWS S3"),
        ("The specified bucket does not exist", "AWS S3"),
        ("Repository not found", "Bitbucket"),
        ("This UserVoice subdomain is currently available", "UserVoice"),
        ("We could not find what you're looking for", "Zendesk"),
        ("No settings were found for this company", "Zendesk"),
        ("project not found", "Heroku"),
        ("404 Not Found", "Fastly"),
        ("The feed has not been found", "Wordpress.com"),
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        from urllib.parse import urlparse
        parsed = urlparse(endpoint.url)
        # Only check apex/root
        if parsed.path not in ("", "/"):
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        for indicator, service in self.TAKEOVER_INDICATORS:
            if indicator.lower() in result.body.lower():
                self._add_finding(
                    vuln_type="SubdomainTakeover",
                    severity="critical",
                    title=f"Potential Subdomain Takeover ({service})",
                    url=endpoint.url,
                    description=(
                        f"Response matches '{service}' unclaimed resource pattern. "
                        "This domain may be vulnerable to subdomain takeover."
                    ),
                    evidence=f"Indicator: '{indicator}'",
                    confidence=80,
                    cwe="CWE-285",
                    cvss=9.3,
                    exploitability="Probable",
                )
                break
        return self.findings


class CachePoisoningModule(BaseModule):
    MODULE_NAME = "CachePoisoning"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        from urllib.parse import urlparse
        if urlparse(endpoint.url).path not in ("", "/"):
            return []

        # Check Cache-Control header
        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        cache_control = result.headers.get("Cache-Control", "")
        vary = result.headers.get("Vary", "")

        if not cache_control:
            self._add_finding(
                vuln_type="CachePoisoning",
                severity="low",
                title="Missing Cache-Control Header",
                url=endpoint.url,
                description="No Cache-Control header found. Responses may be cached by proxies unintentionally.",
                confidence=70,
                cwe="CWE-525",
                cvss=3.7,
                exploitability="Passive",
            )
        elif "public" in cache_control and "no-store" not in cache_control:
            # Test injecting a cache-busting header
            marker = "x-websentinel-probe"
            r2 = self.engine.get(
                endpoint.url,
                extra_headers={marker: "websentinel"},
            )
            if r2.ok and marker in r2.body.lower():
                self._add_finding(
                    vuln_type="CachePoisoning",
                    severity="high",
                    title="Potential Web Cache Poisoning",
                    url=endpoint.url,
                    description="Injected header value was reflected in cached response.",
                    confidence=72,
                    cwe="CWE-444",
                    cvss=8.1,
                    exploitability="Probable",
                )
        return self.findings


class InsecureDeserializationModule(BaseModule):
    MODULE_NAME = "InsecureDeserialization"

    DESERIALIZATION_PATTERNS = [
        "java.io.ObjectInputStream", "java.lang.Runtime",
        "rO0AB", "aced0005",  # Java serialized object magic bytes in base64/hex
        "O:8:", "a:2:{",      # PHP serialized patterns
        "__reduce__", "pickle",
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        body_combined = result.body + " ".join(
            f"{k}={v}" for k, v in result.headers.items()
        )

        for pattern in self.DESERIALIZATION_PATTERNS:
            if pattern.lower() in body_combined.lower():
                self._add_finding(
                    vuln_type="InsecureDeserialization",
                    severity="high",
                    title="Potential Insecure Deserialization",
                    url=endpoint.url,
                    description=(
                        f"Serialization-related pattern '{pattern}' detected in response. "
                        "This may indicate unsanitized deserialization of user-controlled data."
                    ),
                    evidence=f"Pattern: {pattern}",
                    confidence=60,
                    cwe="CWE-502",
                    cvss=9.8,
                    exploitability="Passive",
                )
                break
        return self.findings
