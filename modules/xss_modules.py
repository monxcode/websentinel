"""
WebSentinel Framework - XSS Modules
Reflected, Stored, and DOM-based XSS scanners + CSRF detection.
"""

from typing import List
from .base_module import BaseModule
from core.scorer import Finding
from core.scorer import Finding
from core.crawler import Endpoint
from utils.helpers import inject_param
import config


class XSSModule(BaseModule):
    MODULE_NAME = "XSS"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject():
            return []

        # Test URL parameters
        if endpoint.params:
            self._test_params(endpoint)

        # Test form inputs
        if endpoint.forms:
            self._test_forms(endpoint)

        return self.findings

    def _test_params(self, endpoint: Endpoint):
        baseline = self.engine.get(endpoint.url)
        if not baseline.ok:
            return

        for param in endpoint.params:
            for payload in config.XSS_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue

                reflected = self.analyzer.detect_xss_reflection(result.body)
                if reflected or self.analyzer.detect_reflection(result.body, payload):
                    # Check if inside executable context
                    ct = result.headers.get("Content-Type", "")
                    is_html = "html" in ct.lower() or not ct

                    self._add_finding(
                        vuln_type="XSS",
                        severity="high" if is_html else "medium",
                        title=f"Reflected XSS in parameter '{param}'",
                        url=endpoint.url,
                        description=(
                            f"XSS payload is reflected unencoded in the response "
                            f"for parameter '{param}'. "
                            f"Content-Type: {ct or 'text/html'}"
                        ),
                        evidence=f"Payload reflected: {payload[:80]}",
                        parameter=param,
                        confidence=85,
                        cwe="CWE-79",
                        cvss=7.4,
                        exploitability="Probable",
                    )
                    break

    def _test_forms(self, endpoint: Endpoint):
        for form in endpoint.forms:
            fields = form.get("fields", [])
            text_fields = [f for f in fields if f.get("type", "text") not in
                          ("submit", "button", "image", "file", "hidden", "password")]
            if not text_fields:
                continue

            # Get baseline of form action
            baseline = self.engine.get(form["action"])

            for field in text_fields:
                for payload in config.XSS_PAYLOADS[:3]:
                    data = {f["name"]: "test" for f in fields}
                    data[field["name"]] = payload
                    result = self.engine.post(form["action"], data=data)
                    if not result.ok:
                        continue
                    if self.analyzer.detect_reflection(result.body, payload):
                        self._add_finding(
                            vuln_type="XSS",
                            severity="high",
                            title=f"Reflected XSS via form field '{field['name']}'",
                            url=form["action"],
                            description=f"XSS payload reflected via form POST to {form['action']}",
                            evidence=f"Field: {field['name']}, Payload: {payload[:60]}",
                            parameter=field["name"],
                            confidence=82,
                            cwe="CWE-79",
                            cvss=7.4,
                            exploitability="Probable",
                        )
                        break


class StoredXSSModule(BaseModule):
    MODULE_NAME = "StoredXSS"

    MARKER = "websentinel_xss_marker_test"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        """Detect potential stored XSS by checking if submitted data persists."""
        if not self._should_inject():
            return []

        for form in endpoint.forms:
            if form["method"] != "POST":
                continue
            fields = form.get("fields", [])
            text_fields = [f for f in fields if f.get("type") in ("text", "textarea", None, "")]
            if not text_fields:
                continue

            for field in text_fields:
                # Submit a harmless unique marker
                data = {f["name"]: "test" for f in fields}
                data[field["name"]] = f'<b class="{self.MARKER}">{self.MARKER}</b>'
                result = self.engine.post(form["action"], data=data)
                if not result.ok:
                    continue

                # Check if marker persists on page or in linked pages
                if self.MARKER in result.body:
                    self._add_finding(
                        vuln_type="StoredXSS",
                        severity="critical",
                        title=f"Potential Stored XSS via form field '{field['name']}'",
                        url=form["action"],
                        description=(
                            "Submitted HTML content appears to be stored and returned "
                            f"unescaped in the response for field '{field['name']}'."
                        ),
                        evidence=f"Marker '{self.MARKER}' found in response after POST",
                        parameter=field["name"],
                        confidence=80,
                        cwe="CWE-79",
                        cvss=9.0,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class DOMXSSModule(BaseModule):
    MODULE_NAME = "DOMBasedXSS"

    DOM_SINKS = [
        "document.write(", "document.writeln(", "innerHTML",
        "outerHTML", "eval(", "setTimeout(", "setInterval(",
        ".src=", "location.href", "location.replace(",
    ]
    DOM_SOURCES = [
        "location.hash", "location.search", "document.URL",
        "document.referrer", "window.name",
    ]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        result = self.engine.get(endpoint.url)
        if not result.ok:
            return []

        body = result.body
        found_sinks = [s for s in self.DOM_SINKS if s in body]
        found_sources = [s for s in self.DOM_SOURCES if s in body]

        if found_sinks and found_sources:
            self._add_finding(
                vuln_type="DOMBasedXSS",
                severity="medium",
                title="Potential DOM-Based XSS",
                url=endpoint.url,
                description=(
                    "The page contains DOM sources flowing into DOM sinks, "
                    "which may enable DOM-based XSS. Manual verification recommended."
                ),
                evidence=(
                    f"Sources: {', '.join(found_sources[:3])} | "
                    f"Sinks: {', '.join(found_sinks[:3])}"
                ),
                confidence=55,
                cwe="CWE-79",
                cvss=6.1,
                exploitability="Passive",
            )
        return self.findings


class CSRFModule(BaseModule):
    MODULE_NAME = "CSRF"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._active_probing():
            return []

        for form in endpoint.forms:
            if form["method"] != "POST":
                continue
            fields = form.get("fields", [])
            field_names = [f["name"].lower() for f in fields]
            field_types = [f.get("type", "text").lower() for f in fields]

            has_csrf_token = any(
                name in ("csrf_token", "csrftoken", "_token", "csrf",
                         "authenticity_token", "_csrf_token", "__requestverificationtoken")
                for name in field_names
            )
            has_hidden_token = any(
                t == "hidden" and "token" in n
                for t, n in zip(field_types, field_names)
            )

            if not has_csrf_token and not has_hidden_token:
                self._add_finding(
                    vuln_type="CSRF",
                    severity="medium",
                    title=f"Missing CSRF Protection on form: {form['action'][:60]}",
                    url=form["action"],
                    description=(
                        "POST form lacks CSRF token. State-changing operations without "
                        "CSRF protection may be exploitable via cross-site request forgery."
                    ),
                    evidence=f"Form fields: {', '.join(field_names[:5])}",
                    confidence=72,
                    cwe="CWE-352",
                    cvss=6.5,
                    exploitability="Passive",
                )
        return self.findings
