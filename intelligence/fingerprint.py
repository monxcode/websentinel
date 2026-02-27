"""
WebSentinel Framework - Technology Fingerprinting
Passive detection of CMS, frameworks, servers, and tech stacks.
"""

from typing import Dict, List, Optional, Set
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


class TechFingerprint:
    """Container for detected technologies."""

    def __init__(self):
        self.server: Optional[str] = None
        self.cms: Optional[str] = None
        self.frameworks: List[str] = []
        self.languages: List[str] = []
        self.headers_raw: Dict = {}
        self.all_detected: Set[str] = set()

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "cms": self.cms,
            "frameworks": self.frameworks,
            "languages": self.languages,
            "technologies": list(self.all_detected),
        }


class FingerprintEngine:
    """
    Passive technology fingerprinting from HTTP responses.
    Never sends extra requests — purely analyzes response data.
    """

    def fingerprint(
        self,
        headers: Dict,
        body: str,
        cookies: Dict = None,
    ) -> TechFingerprint:
        """
        Analyze response headers and body to detect tech stack.
        """
        fp = TechFingerprint()
        fp.headers_raw = headers
        cookies = cookies or {}

        # Combine all text for scanning
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        combined = header_str + " " + body[:8000]

        fp.server = self._detect_server(headers)
        fp.cms = self._detect_cms(combined)
        fp.frameworks = self._detect_frameworks(combined, cookies)
        fp.languages = self._detect_languages(headers, body)

        if fp.server:
            fp.all_detected.add(fp.server)
        if fp.cms:
            fp.all_detected.add(fp.cms)
        fp.all_detected.update(fp.frameworks)
        fp.all_detected.update(fp.languages)

        return fp

    def _detect_server(self, headers: Dict) -> Optional[str]:
        """Detect web server from response headers."""
        server_header = headers.get("Server", "") or headers.get("server", "")
        powered_by = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
        combined = f"{server_header} {powered_by}"

        for server, patterns in config.SERVER_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in combined.lower():
                    # Include version if available
                    import re
                    ver_match = re.search(r"[\d.]+", server_header)
                    if ver_match and len(ver_match.group()) > 1:
                        return f"{server}/{ver_match.group()}"
                    return server
        return None

    def _detect_cms(self, content: str) -> Optional[str]:
        """Detect CMS from page content and headers."""
        content_lower = content.lower()
        for cms, patterns in config.CMS_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    return cms
        return None

    def _detect_frameworks(self, content: str, cookies: Dict) -> List[str]:
        """Detect frontend/backend frameworks."""
        detected = []
        content_lower = content.lower()
        cookie_str = " ".join(f"{k}={v}" for k, v in cookies.items()).lower()
        combined = content_lower + " " + cookie_str

        for fw, patterns in config.FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in combined:
                    if fw not in detected:
                        detected.append(fw)
                    break
        return detected

    def _detect_languages(self, headers: Dict, body: str) -> List[str]:
        """Detect programming languages from various signals."""
        langs = []
        powered = (headers.get("X-Powered-By", "") or "").lower()
        server  = (headers.get("Server", "") or "").lower()
        combined = f"{powered} {server} {body[:3000]}".lower()

        lang_patterns = {
            "PHP":    ["x-powered-by: php", ".php", "<?php", "phpsessid"],
            "Python": ["wsgi", "werkzeug", "gunicorn", "python", "django", "flask"],
            "Ruby":   ["x-powered-by: phusion passenger", "ruby", "_rails_"],
            "Java":   ["jsessionid", "java", "tomcat", "spring", ".jsp", ".do"],
            "Node.js":["express", "node.js", "connect/"],
            "ASP.NET":["asp.net", "__viewstate", "x-aspnet"],
            "Go":     ["go/1.", "gin-gonic"],
            "Rust":   ["actix-web", "rocket"],
        }
        for lang, patterns in lang_patterns.items():
            for p in patterns:
                if p in combined:
                    if lang not in langs:
                        langs.append(lang)
                    break
        return langs

    def detect_waf(self, headers: Dict, body: str) -> Optional[str]:
        """Detect WAF presence from headers and error pages."""
        waf_signatures = {
            "Cloudflare":  ["cf-ray", "cloudflare"],
            "AWS WAF":     ["awswaf", "x-amzn-requestid"],
            "Akamai":      ["akamaighost", "x-akamai"],
            "Sucuri":      ["x-sucuri-id", "sucuri"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP":   ["bigipserver", "f5"],
            "Imperva":     ["x-iinfo", "imperva", "incapsula"],
            "Barracuda":   ["barracuda"],
        }
        header_str = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers.items())
        combined = f"{header_str} {body[:2000]}".lower()

        for waf, patterns in waf_signatures.items():
            if any(p in combined for p in patterns):
                return waf
        return None
