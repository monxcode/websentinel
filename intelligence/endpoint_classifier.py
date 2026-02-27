"""
WebSentinel Framework - Endpoint Classifier
Classifies and prioritizes endpoints for scanning.
"""

from typing import List, Dict, Tuple
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from core.crawler import Endpoint


class EndpointClassifier:
    """
    Analyzes discovered endpoints to determine scan priority
    and relevant vulnerability modules.
    """

    PRIORITY_MAP = {
        "admin":   10,
        "auth":    9,
        "api":     8,
        "dynamic": 6,
        "static":  2,
        "unknown": 4,
    }

    def classify_all(self, endpoints: List[Endpoint]) -> List[Dict]:
        """
        Return endpoints sorted by scan priority with module recommendations.
        """
        classified = []
        for ep in endpoints:
            info = {
                "endpoint": ep,
                "priority": self.PRIORITY_MAP.get(ep.endpoint_type, 4),
                "modules": self._recommended_modules(ep),
                "has_params": bool(ep.params),
                "has_forms": bool(ep.forms),
            }
            classified.append(info)
        return sorted(classified, key=lambda x: x["priority"], reverse=True)

    def _recommended_modules(self, ep: Endpoint) -> List[str]:
        """Determine which scan modules apply to this endpoint."""
        modules = ["SecurityHeaders", "InfoDisclosure", "Clickjacking", "CORS"]

        if ep.endpoint_type in ("admin", "auth") or ep.endpoint_type == "dynamic":
            modules += ["BrokenAuth", "SessionAnalysis", "CSRF"]

        if ep.params or ep.forms:
            modules += [
                "SQLInjection", "XSS", "CmdInjection", "NoSQLInjection",
                "LDAPInjection", "XMLInjection", "PathTraversal",
                "LFI", "OpenRedirect", "SSRF", "IDOR",
            ]

        if ep.endpoint_type == "api":
            modules += ["APIMisconfiguration", "MassAssignment", "RateLimiting"]

        if ep.endpoint_type == "admin":
            modules += ["PrivilegeEscalation", "BrokenAccessControl"]

        # File upload detection
        for form in ep.forms:
            for field in form.get("fields", []):
                if field.get("type") == "file":
                    modules.append("FileUpload")
                    break

        return list(dict.fromkeys(modules))  # deduplicate preserving order

    def get_attack_surface_summary(self, endpoints: List[Endpoint]) -> Dict:
        """Summarize the attack surface."""
        type_counts = {}
        param_count = 0
        form_count = 0
        total_params = set()

        for ep in endpoints:
            t = ep.endpoint_type
            type_counts[t] = type_counts.get(t, 0) + 1
            if ep.params:
                param_count += 1
                total_params.update(ep.params.keys())
            form_count += len(ep.forms)

        return {
            "total_endpoints": len(endpoints),
            "by_type": type_counts,
            "endpoints_with_params": param_count,
            "total_forms": form_count,
            "unique_param_names": len(total_params),
            "param_names": list(total_params)[:20],
        }
