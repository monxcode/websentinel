"""
WebSentinel Framework - Injection Modules
SQL, NoSQL, Command, LDAP, XML injection scanners.
"""

from typing import List
from .base_module import BaseModule
from core.scorer import Finding
from core.scorer import Finding
from core.crawler import Endpoint
from utils.helpers import inject_all_params, inject_param
import config


class SQLInjectionModule(BaseModule):
    MODULE_NAME = "SQLInjection"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject():
            return []
        if not endpoint.params:
            return self._check_forms(endpoint)

        baseline = self.engine.get(endpoint.url)
        if not baseline.ok:
            return []

        for param, injected_url in inject_all_params(endpoint.url, config.SQLI_PAYLOADS[0]):
            for payload in config.SQLI_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                sql_errors = self.analyzer.detect_sql_errors(result.body)
                if sql_errors:
                    self._add_finding(
                        vuln_type="SQLInjection",
                        severity="critical",
                        title=f"SQL Injection in parameter '{param}'",
                        url=endpoint.url,
                        description=(
                            f"SQL injection vulnerability detected. "
                            f"The parameter '{param}' reflects SQL error messages when injected with: {payload}"
                        ),
                        evidence=f"Errors: {', '.join(sql_errors[:3])}",
                        parameter=param,
                        confidence=90,
                        cwe="CWE-89",
                        cvss=9.8,
                        exploitability="Probable",
                    )
                    break

                diff = self.diff.compare_results(
                    baseline, result,
                    error_patterns=config.SQLI_ERROR_PATTERNS,
                )
                if diff.is_anomalous and diff.indicators:
                    self._add_finding(
                        vuln_type="SQLInjection",
                        severity="high",
                        title=f"Potential SQL Injection in parameter '{param}'",
                        url=endpoint.url,
                        description=f"Behavioral anomaly detected for parameter '{param}' with payload: {payload}",
                        evidence="; ".join(diff.indicators),
                        parameter=param,
                        confidence=60,
                        cwe="CWE-89",
                        cvss=8.1,
                        exploitability="Probable",
                    )
                    break
        return self.findings

    def _check_forms(self, endpoint: Endpoint) -> List[Finding]:
        """Test SQL injection via form fields."""
        for form in endpoint.forms:
            if form["method"] != "POST":
                continue
            for field in form.get("fields", []):
                fname = field["name"]
                ftype = field.get("type", "text")
                if ftype in ("submit", "button", "image", "file"):
                    continue
                for payload in config.SQLI_PAYLOADS[:3]:
                    data = {f["name"]: "test" for f in form.get("fields", [])}
                    data[fname] = payload
                    result = self.engine.post(form["action"], data=data)
                    if result.ok:
                        errors = self.analyzer.detect_sql_errors(result.body)
                        if errors:
                            self._add_finding(
                                vuln_type="SQLInjection",
                                severity="critical",
                                title=f"SQL Injection in form field '{fname}'",
                                url=form["action"],
                                description=f"SQL error triggered via form field '{fname}'",
                                evidence=", ".join(errors[:2]),
                                parameter=fname,
                                confidence=88,
                                cwe="CWE-89",
                                cvss=9.8,
                                exploitability="Probable",
                            )
                            break
        return self.findings


class NoSQLInjectionModule(BaseModule):
    MODULE_NAME = "NoSQLInjection"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        baseline = self.engine.get(endpoint.url)
        if not baseline.ok:
            return []

        for param in endpoint.params:
            for payload in config.NOSQL_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                diff = self.diff.compare_results(baseline, result)
                if diff.is_anomalous:
                    self._add_finding(
                        vuln_type="NoSQLInjection",
                        severity="high",
                        title=f"NoSQL Injection in parameter '{param}'",
                        url=endpoint.url,
                        description=f"Behavioral anomaly suggests NoSQL injection in '{param}' with payload: {payload}",
                        evidence="; ".join(diff.indicators[:2]),
                        parameter=param,
                        confidence=65,
                        cwe="CWE-943",
                        cvss=8.1,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class CommandInjectionModule(BaseModule):
    MODULE_NAME = "CommandInjection"

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        baseline = self.engine.get(endpoint.url)
        if not baseline.ok:
            return []

        for param in endpoint.params:
            for payload in config.CMD_INJECTION_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                patterns = self.analyzer.detect_cmd_injection_patterns(result.body)
                if patterns:
                    self._add_finding(
                        vuln_type="CommandInjection",
                        severity="critical",
                        title=f"Command Injection in parameter '{param}'",
                        url=endpoint.url,
                        description=(
                            f"Command injection patterns detected in response "
                            f"for parameter '{param}' with payload: {payload}"
                        ),
                        evidence=f"Patterns: {', '.join(patterns)}",
                        parameter=param,
                        confidence=85,
                        cwe="CWE-78",
                        cvss=9.8,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class LDAPInjectionModule(BaseModule):
    MODULE_NAME = "LDAPInjection"

    LDAP_PAYLOADS = ["*", "*)(&", "*)(|", ")(cn=*))(|(cn=*"]
    LDAP_ERROR_PATTERNS = ["ldap", "invalid dn", "entry not found", "directory service"]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        baseline = self.engine.get(endpoint.url)
        if not baseline.ok:
            return []

        for param in endpoint.params:
            for payload in self.LDAP_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                body_lower = result.body.lower()
                if any(p in body_lower for p in self.LDAP_ERROR_PATTERNS):
                    self._add_finding(
                        vuln_type="LDAPInjection",
                        severity="high",
                        title=f"LDAP Injection in parameter '{param}'",
                        url=endpoint.url,
                        description=f"LDAP error or unexpected output detected for '{param}' with payload: {payload}",
                        parameter=param,
                        confidence=70,
                        cwe="CWE-90",
                        cvss=8.0,
                        exploitability="Probable",
                    )
                    break
        return self.findings


class XMLInjectionModule(BaseModule):
    MODULE_NAME = "XMLInjection"

    XML_PAYLOADS = [
        "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>",
        "<test><![CDATA[<script>alert(1)</script>]]></test>",
        "]]>",
        "</test><!--",
    ]
    XML_ERROR_PATTERNS = ["xml", "parsing error", "entity", "malformed", "doctype", "syntax error"]

    def run(self, endpoint: Endpoint) -> List[Finding]:
        if not self._should_inject() or not endpoint.params:
            return []

        for param in endpoint.params:
            for payload in self.XML_PAYLOADS:
                test_url = inject_param(endpoint.url, param, payload)
                result = self.engine.get(test_url)
                if not result.ok:
                    continue
                body_lower = result.body.lower()
                lfi_patterns = self.analyzer.detect_lfi_patterns(result.body)
                xml_errors = [p for p in self.XML_ERROR_PATTERNS if p in body_lower]

                if lfi_patterns:
                    self._add_finding(
                        vuln_type="XMLInjection",
                        severity="critical",
                        title=f"XXE (XML External Entity) in parameter '{param}'",
                        url=endpoint.url,
                        description="XXE injection leads to file disclosure",
                        evidence=f"LFI patterns: {', '.join(lfi_patterns)}",
                        parameter=param,
                        confidence=88,
                        cwe="CWE-611",
                        cvss=9.1,
                        exploitability="Probable",
                    )
                    break
                elif xml_errors:
                    self._add_finding(
                        vuln_type="XMLInjection",
                        severity="medium",
                        title=f"XML Injection in parameter '{param}'",
                        url=endpoint.url,
                        description="XML parsing error suggests XML injection vulnerability",
                        evidence=f"XML errors: {', '.join(xml_errors[:2])}",
                        parameter=param,
                        confidence=60,
                        cwe="CWE-91",
                        cvss=6.1,
                        exploitability="Probable",
                    )
                    break
        return self.findings
