"""
WebSentinel Framework - Response Analyzer
Baseline capture, response diffing, header analysis, and anomaly detection.
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from difflib import SequenceMatcher

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


class ResponseBaseline:
    """Stores baseline response characteristics for anomaly detection."""

    def __init__(self, status: int, body: str, headers: Dict, elapsed: float):
        self.status = status
        self.body = body
        self.headers = headers
        self.elapsed = elapsed
        self.length = len(body)
        self.body_hash = hashlib.md5(body.encode(errors="ignore")).hexdigest()
        self.word_count = len(body.split())


class ResponseAnalyzer:
    """
    Comprehensive HTTP response analysis engine.
    Detects reflections, errors, header anomalies, and cookie issues.
    """

    # ─────────────────────────────────────────────
    # BASELINE MANAGEMENT
    # ─────────────────────────────────────────────

    @staticmethod
    def capture_baseline(result) -> ResponseBaseline:
        """Capture baseline from a RequestResult."""
        return ResponseBaseline(
            status=result.status_code,
            body=result.body,
            headers=result.headers,
            elapsed=result.elapsed,
        )

    @staticmethod
    def differs_from_baseline(
        baseline: ResponseBaseline,
        result,
        threshold: float = 0.15,
    ) -> Tuple[bool, Dict]:
        """
        Compare a result against the baseline.
        Returns (is_different, diff_info).
        """
        diff_info = {}

        # Status code change
        if result.status_code != baseline.status:
            diff_info["status_changed"] = {
                "from": baseline.status,
                "to": result.status_code,
            }

        # Content length deviation (>15% change)
        if baseline.length > 0:
            ratio = abs(result.content_length - baseline.length) / baseline.length
            if ratio > threshold:
                diff_info["length_changed"] = {
                    "baseline": baseline.length,
                    "current": result.content_length,
                    "ratio": round(ratio, 3),
                }

        # Body hash changed
        current_hash = hashlib.md5(result.body.encode(errors="ignore")).hexdigest()
        if current_hash != baseline.body_hash:
            # Compute similarity
            sim = SequenceMatcher(None, baseline.body[:2000], result.body[:2000]).ratio()
            if sim < (1 - threshold):
                diff_info["body_changed"] = {"similarity": round(sim, 3)}

        is_different = bool(diff_info)
        return is_different, diff_info

    # ─────────────────────────────────────────────
    # ERROR PATTERN DETECTION
    # ─────────────────────────────────────────────

    @staticmethod
    def detect_sql_errors(body: str) -> List[str]:
        """Find SQL error messages in response body."""
        body_lower = body.lower()
        return [p for p in config.SQLI_ERROR_PATTERNS if p in body_lower]

    @staticmethod
    def detect_cmd_injection_patterns(body: str) -> List[str]:
        """Find command injection output patterns in response body."""
        body_lower = body.lower()
        return [p for p in config.CMD_INJECTION_PATTERNS if p in body_lower]

    @staticmethod
    def detect_lfi_patterns(body: str) -> List[str]:
        """Find LFI success patterns in response body."""
        body_lower = body.lower()
        return [p for p in config.LFI_PATTERNS if p in body_lower]

    @staticmethod
    def detect_ssrf_patterns(body: str) -> List[str]:
        """Find SSRF success patterns in response body."""
        body_lower = body.lower()
        return [p for p in config.SSRF_PATTERNS if p in body_lower]

    # ─────────────────────────────────────────────
    # REFLECTION DETECTION
    # ─────────────────────────────────────────────

    @staticmethod
    def detect_reflection(body: str, payload: str) -> bool:
        """Check if a payload is reflected in the response body."""
        return payload.lower() in body.lower()

    @staticmethod
    def detect_xss_reflection(body: str) -> List[str]:
        """Detect reflected XSS payloads in response."""
        found = []
        for marker in config.XSS_REFLECTION_MARKERS:
            if marker.lower() in body.lower():
                found.append(marker)
        return found

    # ─────────────────────────────────────────────
    # HEADER ANALYSIS
    # ─────────────────────────────────────────────

    @staticmethod
    def analyze_security_headers(headers: Dict) -> Dict:
        """
        Check presence and validity of security headers.
        Returns a dict of findings.
        """
        findings = {
            "missing": [],
            "present": {},
            "misconfigured": [],
        }
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header in config.SECURITY_HEADERS:
            key = header.lower()
            if key in headers_lower:
                findings["present"][header] = headers_lower[key]
                # Check specific header values
                if header == "X-Frame-Options":
                    val = headers_lower[key].upper()
                    if val not in ("DENY", "SAMEORIGIN"):
                        findings["misconfigured"].append(
                            f"X-Frame-Options has weak value: {val}"
                        )
                elif header == "Strict-Transport-Security":
                    val = headers_lower[key]
                    if "max-age" not in val.lower():
                        findings["misconfigured"].append("HSTS missing max-age")
                elif header == "X-Content-Type-Options":
                    val = headers_lower[key].lower()
                    if val != "nosniff":
                        findings["misconfigured"].append(
                            f"X-Content-Type-Options should be 'nosniff', got: {val}"
                        )
            else:
                findings["missing"].append(header)

        return findings

    @staticmethod
    def analyze_cookies(headers: Dict) -> List[Dict]:
        """
        Analyze Set-Cookie headers for security flags.
        Returns list of cookie findings.
        """
        cookie_issues = []
        raw_cookies = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                raw_cookies.append(v)

        for cookie_str in raw_cookies:
            parts = [p.strip().lower() for p in cookie_str.split(";")]
            name = cookie_str.split("=")[0].strip()
            flags = {"httponly": False, "secure": False, "samesite": None}
            for part in parts[1:]:
                if part == "httponly":
                    flags["httponly"] = True
                elif part == "secure":
                    flags["secure"] = True
                elif part.startswith("samesite="):
                    flags["samesite"] = part.split("=", 1)[1]

            issues = []
            if not flags["httponly"]:
                issues.append("Missing HttpOnly flag (XSS risk)")
            if not flags["secure"]:
                issues.append("Missing Secure flag (cleartext transmission risk)")
            if not flags["samesite"]:
                issues.append("Missing SameSite attribute (CSRF risk)")
            elif flags["samesite"] == "none" and not flags["secure"]:
                issues.append("SameSite=None requires Secure flag")

            if issues:
                cookie_issues.append({"cookie": name, "issues": issues})

        return cookie_issues

    @staticmethod
    def analyze_cors(headers: Dict, test_origin: str = "https://evil.com") -> Optional[Dict]:
        """
        Analyze CORS headers for misconfiguration.
        """
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if not acao:
            return None

        finding = {"allow_origin": acao, "allow_credentials": acac}
        if acao == "*" and acac.lower() == "true":
            finding["issue"] = "Wildcard origin with credentials — critical CORS misconfiguration"
            finding["severity"] = "critical"
        elif acao == "*":
            finding["issue"] = "Wildcard CORS origin allows any site to read responses"
            finding["severity"] = "medium"
        elif acao == test_origin:
            finding["issue"] = f"CORS reflects arbitrary origin: {test_origin}"
            finding["severity"] = "high"
        elif acao.lower() == "null":
            finding["issue"] = "CORS origin set to 'null' — exploitable via sandboxed iframes"
            finding["severity"] = "high"
        else:
            return None

        return finding

    @staticmethod
    def check_clickjacking(headers: Dict) -> Optional[Dict]:
        """Check if page is vulnerable to clickjacking."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        xfo = headers_lower.get("x-frame-options", "")
        csp = headers_lower.get("content-security-policy", "")

        has_xfo = bool(xfo and xfo.upper() in ("DENY", "SAMEORIGIN"))
        has_csp_frame = "frame-ancestors" in csp.lower()

        if not has_xfo and not has_csp_frame:
            return {
                "issue": "No X-Frame-Options or CSP frame-ancestors — page embeddable in iframes",
                "severity": "medium",
            }
        return None

    @staticmethod
    def detect_server_info(headers: Dict) -> Dict:
        """Detect server/technology info disclosure in headers."""
        disclosures = {}
        sensitive = ["server", "x-powered-by", "x-aspnet-version",
                     "x-aspnetmvc-version", "x-generator", "x-runtime"]
        for h in sensitive:
            val = headers.get(h, "") or headers.get(h.title(), "")
            if val:
                disclosures[h] = val
        return disclosures

    @staticmethod
    def detect_open_redirect(result, payload: str) -> bool:
        """Check if response redirects to an injected URL."""
        if result.redirected:
            return payload.rstrip("/") in result.final_url
        location = result.headers.get("Location", "")
        if location:
            return payload.rstrip("/") in location
        return False
