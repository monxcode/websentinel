"""
WebSentinel Framework - Scoring Engine
Risk scoring, severity weighting, and final security grade calculation.
"""

from typing import List, Dict, Tuple
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


class Finding:
    """Represents a single vulnerability finding."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(
        self,
        vuln_type: str,
        severity: str,
        title: str,
        url: str,
        description: str,
        evidence: str = "",
        parameter: str = "",
        confidence: int = 70,
        remediation: str = "",
        cwe: str = "",
        cvss: float = 0.0,
        exploitability: str = "Passive",
    ):
        self.vuln_type = vuln_type
        self.severity = severity.lower()
        self.title = title
        self.url = url
        self.description = description
        self.evidence = evidence[:500] if evidence else ""
        self.parameter = parameter
        self.confidence = min(100, max(0, confidence))
        self.remediation = remediation
        self.cwe = cwe
        self.cvss = cvss
        self.exploitability = exploitability

    def to_dict(self) -> dict:
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "confidence_label": self._confidence_label(),
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "exploitability": self.exploitability,
        }

    def _confidence_label(self) -> str:
        if self.confidence >= 90: return "Confirmed"
        if self.confidence >= 70: return "Probable"
        if self.confidence >= 50: return "Possible"
        return "Speculative"

    @property
    def severity_rank(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity, 5)


class ScoringEngine:
    """
    Calculates security scores, grades, and risk distributions.
    """

    MAX_SCORE = 100
    DEDUCTION_CAP_PER_SEVERITY = {
        "critical": 40,
        "high": 30,
        "medium": 20,
        "low": 10,
        "info": 0,
    }

    def __init__(self, findings: List[Finding]):
        self.findings = sorted(findings, key=lambda f: f.severity_rank)

    def calculate_score(self) -> int:
        """
        Calculate final security score (0–100).
        Deducts points based on severity and confidence-weighted findings.
        """
        if not self.findings:
            return self.MAX_SCORE

        deductions = 0
        severity_deductions: Dict[str, int] = {s: 0 for s in config.SEVERITY_WEIGHTS}

        for f in self.findings:
            weight = config.SEVERITY_WEIGHTS.get(f.severity, 0)
            # Weight by confidence
            weighted = weight * (f.confidence / 100)
            cap = self.DEDUCTION_CAP_PER_SEVERITY.get(f.severity, 0)
            current = severity_deductions.get(f.severity, 0)

            to_deduct = min(weighted, max(0, cap - current))
            severity_deductions[f.severity] = current + to_deduct
            deductions += to_deduct

        score = max(0, int(self.MAX_SCORE - deductions))
        return score

    def get_grade(self, score: int) -> str:
        """Map score to letter grade."""
        for grade, (low, high) in config.GRADE_THRESHOLDS.items():
            if low <= score <= high:
                return grade
        return "F"

    def risk_distribution(self) -> Dict[str, int]:
        """Count findings by severity."""
        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            dist[f.severity] = dist.get(f.severity, 0) + 1
        return dist

    def top_findings(self, n: int = 5) -> List[Finding]:
        """Return top N most severe findings."""
        return self.findings[:n]

    def exploitability_summary(self) -> Dict[str, int]:
        """Summarize findings by exploitability."""
        summary = {}
        for f in self.findings:
            summary[f.exploitability] = summary.get(f.exploitability, 0) + 1
        return summary

    def type_summary(self) -> Dict[str, int]:
        """Summarize findings by vulnerability type."""
        summary = {}
        for f in self.findings:
            summary[f.vuln_type] = summary.get(f.vuln_type, 0) + 1
        return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))

    def generate_risk_matrix(self) -> List[Dict]:
        """Generate a risk matrix entry per finding."""
        matrix = []
        for f in self.findings:
            matrix.append({
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "exploitability": f.exploitability,
                "url": f.url[:80],
                "risk_level": self._risk_level(f),
            })
        return matrix

    @staticmethod
    def _risk_level(f: Finding) -> str:
        """Compute combined risk level."""
        if f.severity == "critical" and f.confidence >= 70:
            return "CRITICAL"
        if f.severity in ("critical", "high") and f.confidence >= 50:
            return "HIGH"
        if f.severity in ("high", "medium") and f.confidence >= 50:
            return "MEDIUM"
        return "LOW"
