"""
WebSentinel Framework - JSON Report Generator
Structured JSON output with full scan results.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from core.scorer import Finding, ScoringEngine


class JSONReporter:
    """Generates structured JSON security reports."""

    def __init__(
        self,
        target: str,
        scan_profile: str,
        endpoints: List,
        findings: List[Finding],
        fingerprint: Dict,
        attack_surface: Dict,
        waf: str = None,
        auth_summary: Dict = None,
    ):
        self.target = target
        self.scan_profile = scan_profile
        self.endpoints = endpoints
        self.findings = findings
        self.fingerprint = fingerprint
        self.attack_surface = attack_surface
        self.waf = waf
        self.auth_summary = auth_summary or {"auth_method": "none", "success": False}

        scorer = ScoringEngine(findings)
        self.score = scorer.calculate_score()
        self.grade = scorer.get_grade(self.score)
        self.risk_dist = scorer.risk_distribution()
        self.type_summary = scorer.type_summary()

    def generate(self) -> Dict:
        """Build the full report dictionary."""
        return {
            "websentinel_report": {
                "version": config.VERSION,
                "target": self.target,
                "scan_profile": self.scan_profile,
                "scan_date": datetime.now().isoformat(),
                "total_endpoints": len(self.endpoints),
                "total_findings": len(self.findings),
                "security_score": self.score,
                "security_grade": self.grade,
                "attack_surface_summary": self.attack_surface,
                "technology_fingerprint": self.fingerprint,
                "waf_detected": self.waf,
                "authentication": self.auth_summary,
                "risk_distribution": self.risk_dist,
                "vulnerability_type_summary": self.type_summary,
                "vulnerabilities": [f.to_dict() for f in self.findings],
                "endpoints": [ep.to_dict() for ep in self.endpoints[:50]],  # cap for readability
            }
        }

    def save(self, path: str = None) -> str:
        """Save JSON report to file."""
        if path is None:
            os.makedirs(config.OUTPUT_DIR, exist_ok=True)
            path = os.path.join(config.OUTPUT_DIR, config.JSON_REPORT_NAME)

        report = self.generate()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return path
