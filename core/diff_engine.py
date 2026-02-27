"""
WebSentinel Framework - Diff Engine
Compares responses to detect behavioral anomalies caused by injected payloads.
"""

import hashlib
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple


class DiffResult:
    """Container for response comparison results."""

    def __init__(
        self,
        is_anomalous: bool,
        similarity: float,
        status_changed: bool,
        length_delta: int,
        length_ratio: float,
        new_content: List[str],
        indicators: List[str],
    ):
        self.is_anomalous = is_anomalous
        self.similarity = similarity
        self.status_changed = status_changed
        self.length_delta = length_delta
        self.length_ratio = length_ratio
        self.new_content = new_content
        self.indicators = indicators

    def __bool__(self):
        return self.is_anomalous

    def to_dict(self) -> dict:
        return {
            "anomalous": self.is_anomalous,
            "similarity": round(self.similarity, 3),
            "status_changed": self.status_changed,
            "length_delta": self.length_delta,
            "indicators": self.indicators,
        }


class DiffEngine:
    """
    Compares baseline vs probe responses to detect injection-induced anomalies.
    Used by vulnerability modules to confirm findings.
    """

    def __init__(self, threshold: float = 0.10, max_body_compare: int = 4000):
        self.threshold = threshold
        self.max_body_compare = max_body_compare

    def compare(
        self,
        baseline_status: int,
        baseline_body: str,
        probe_status: int,
        probe_body: str,
        error_patterns: List[str] = None,
        reflection_payloads: List[str] = None,
    ) -> DiffResult:
        """
        Full comparison between baseline and probe response.
        """
        indicators = []
        is_anomalous = False

        # Status code change
        status_changed = (probe_status != baseline_status)
        if status_changed:
            indicators.append(f"Status changed: {baseline_status} → {probe_status}")
            if probe_status in (500, 501, 502, 503):
                indicators.append("Server error — possible injection impact")
                is_anomalous = True

        # Body similarity
        b1 = baseline_body[:self.max_body_compare].lower()
        b2 = probe_body[:self.max_body_compare].lower()
        similarity = SequenceMatcher(None, b1, b2).ratio()
        length_delta = len(probe_body) - len(baseline_body)
        length_ratio = abs(length_delta) / max(len(baseline_body), 1)

        if length_ratio > self.threshold:
            indicators.append(
                f"Content length deviation: {length_delta:+d} bytes ({length_ratio:.1%})"
            )
            is_anomalous = True

        # Error patterns in probe response
        if error_patterns:
            probe_lower = probe_body.lower()
            for pattern in error_patterns:
                if pattern in probe_lower and pattern not in baseline_body.lower():
                    indicators.append(f"Error pattern detected: '{pattern}'")
                    is_anomalous = True

        # Reflection detection
        if reflection_payloads:
            for payload in reflection_payloads:
                if payload.lower() in probe_body.lower():
                    indicators.append(f"Payload reflected in response: {payload[:50]}")
                    is_anomalous = True

        # Extract newly added lines for context
        new_content = self._extract_new_lines(baseline_body, probe_body)

        return DiffResult(
            is_anomalous=is_anomalous,
            similarity=similarity,
            status_changed=status_changed,
            length_delta=length_delta,
            length_ratio=length_ratio,
            new_content=new_content[:5],
            indicators=indicators,
        )

    @staticmethod
    def _extract_new_lines(old: str, new: str) -> List[str]:
        """Find lines in new that are not in old."""
        old_lines = set(l.strip() for l in old.splitlines() if l.strip())
        new_lines = []
        for line in new.splitlines():
            stripped = line.strip()
            if stripped and stripped not in old_lines and len(stripped) > 5:
                new_lines.append(stripped[:120])
        return new_lines

    def compare_results(self, baseline, probe, **kwargs) -> DiffResult:
        """
        Convenience wrapper accepting RequestResult objects directly.
        """
        return self.compare(
            baseline_status=baseline.status_code,
            baseline_body=baseline.body,
            probe_status=probe.status_code,
            probe_body=probe.body,
            **kwargs,
        )
