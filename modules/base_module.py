"""
WebSentinel Framework - Base Vulnerability Module
All scanning modules inherit from BaseModule.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.scorer import Finding
from core.crawler import Endpoint


class BaseModule(ABC):
    """Abstract base class for all vulnerability scanning modules."""

    MODULE_NAME = "BaseModule"
    MODULE_DESCRIPTION = ""

    def __init__(self, engine, analyzer, diff_engine, profile: dict, logger=None):
        """
        :param engine: RequestEngine instance
        :param analyzer: ResponseAnalyzer instance
        :param diff_engine: DiffEngine instance
        :param profile: Scan profile config dict
        :param logger: Logger instance
        """
        self.engine = engine
        self.analyzer = analyzer
        self.diff = diff_engine
        self.profile = profile
        self.logger = logger
        self.findings: List[Finding] = []

    @abstractmethod
    def run(self, endpoint: Endpoint) -> List[Finding]:
        """Run the module against a single endpoint. Returns list of findings."""
        pass

    def log(self, msg: str):
        if self.logger:
            self.logger.debug(f"[{self.MODULE_NAME}] {msg}")

    def found(self, msg: str):
        if self.logger:
            self.logger.vuln(f"[{self.MODULE_NAME}] {msg}")

    def _add_finding(
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
    ) -> Finding:
        f = Finding(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            url=url,
            description=description,
            evidence=evidence,
            parameter=parameter,
            confidence=confidence,
            remediation=remediation,
            cwe=cwe,
            cvss=cvss,
            exploitability=exploitability,
        )
        self.findings.append(f)
        self.found(f"{severity.upper()}: {title} @ {url[:60]}")
        return f

    def _should_inject(self) -> bool:
        """Check if injection tests are allowed in current profile."""
        return self.profile.get("injection_tests", False)

    def _should_fuzz(self) -> bool:
        """Check if fuzzing is allowed in current profile."""
        return self.profile.get("fuzz_params", False)

    def _active_probing(self) -> bool:
        return self.profile.get("active_probing", False)
