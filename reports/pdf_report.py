"""
WebSentinel Framework - PDF Report Generator
Professional PDF security report using ReportLab.
"""

import os
from datetime import datetime
from typing import List, Dict

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from core.scorer import Finding, ScoringEngine
from intelligence.risk_matrix import RiskMatrix


# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────
PALETTE = {
    "bg_dark":   colors.HexColor("#0D1117"),
    "bg_card":   colors.HexColor("#161B22"),
    "accent":    colors.HexColor("#00D9FF"),
    "critical":  colors.HexColor("#FF3B3B"),
    "high":      colors.HexColor("#FF7A00"),
    "medium":    colors.HexColor("#FFD600"),
    "low":       colors.HexColor("#00C853"),
    "info":      colors.HexColor("#2979FF"),
    "text":      colors.HexColor("#C9D1D9"),
    "subtext":   colors.HexColor("#8B949E"),
    "white":     colors.white,
    "grade_a":   colors.HexColor("#00C853"),
    "grade_b":   colors.HexColor("#8BC34A"),
    "grade_c":   colors.HexColor("#FFD600"),
    "grade_d":   colors.HexColor("#FF7A00"),
    "grade_f":   colors.HexColor("#FF3B3B"),
}

SEV_COLORS = {
    "critical": PALETTE["critical"],
    "high":     PALETTE["high"],
    "medium":   PALETTE["medium"],
    "low":      PALETTE["low"],
    "info":     PALETTE["info"],
}


def _grade_color(grade: str):
    mapping = {"A": "grade_a", "B": "grade_b", "C": "grade_c", "D": "grade_d", "F": "grade_f"}
    return PALETTE.get(mapping.get(grade, "accent"), PALETTE["accent"])


class PDFReporter:
    """Generates a professional A4 PDF security assessment report."""

    def __init__(
        self,
        target: str,
        scan_profile: str,
        endpoints: List,
        findings: List[Finding],
        fingerprint: Dict,
        attack_surface: Dict,
        waf: str = None,
    ):
        self.target = target
        self.scan_profile = scan_profile
        self.endpoints = endpoints
        self.findings = sorted(findings, key=lambda f: f.severity_rank)
        self.fingerprint = fingerprint
        self.attack_surface = attack_surface
        self.waf = waf

        scorer = ScoringEngine(findings)
        self.score = scorer.calculate_score()
        self.grade = scorer.get_grade(self.score)
        self.risk_dist = scorer.risk_distribution()
        self.risk_matrix_engine = RiskMatrix()

        self.styles = self._build_styles()
        self.story = []

    # ─────────────────────────────────────────────
    # STYLES
    # ─────────────────────────────────────────────
    def _build_styles(self):
        base = getSampleStyleSheet()
        custom = {}

        custom["cover_title"] = ParagraphStyle(
            "cover_title", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=28,
            textColor=PALETTE["accent"], alignment=TA_CENTER, spaceAfter=6,
        )
        custom["cover_sub"] = ParagraphStyle(
            "cover_sub", parent=base["Normal"],
            fontName="Helvetica", fontSize=12,
            textColor=PALETTE["text"], alignment=TA_CENTER, spaceAfter=4,
        )
        custom["h1"] = ParagraphStyle(
            "h1", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=18,
            textColor=PALETTE["accent"], spaceBefore=12, spaceAfter=6,
        )
        custom["h2"] = ParagraphStyle(
            "h2", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=13,
            textColor=PALETTE["text"], spaceBefore=8, spaceAfter=4,
        )
        custom["body"] = ParagraphStyle(
            "body", parent=base["Normal"],
            fontName="Helvetica", fontSize=9,
            textColor=PALETTE["text"], spaceAfter=4, leading=13,
        )
        custom["small"] = ParagraphStyle(
            "small", parent=base["Normal"],
            fontName="Helvetica", fontSize=8,
            textColor=PALETTE["subtext"], spaceAfter=2,
        )
        custom["code"] = ParagraphStyle(
            "code", parent=base["Normal"],
            fontName="Courier", fontSize=8,
            textColor=PALETTE["accent"], spaceAfter=3,
        )
        custom["table_header"] = ParagraphStyle(
            "table_header", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=9,
            textColor=PALETTE["white"], alignment=TA_LEFT,
        )
        return custom

    # ─────────────────────────────────────────────
    # DOCUMENT BUILD
    # ─────────────────────────────────────────────
    def generate(self, path: str = None) -> str:
        if path is None:
            os.makedirs(config.OUTPUT_DIR, exist_ok=True)
            path = os.path.join(config.OUTPUT_DIR, config.PDF_REPORT_NAME)

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=18*mm, rightMargin=18*mm,
            topMargin=18*mm, bottomMargin=18*mm,
            title=f"WebSentinel Security Report — {self.target}",
            author="WebSentinel Framework",
        )

        self._add_cover()
        self._add_executive_summary()
        self._add_attack_surface()
        self._add_risk_distribution()
        self._add_tech_fingerprint()
        self._add_findings()
        self._add_risk_matrix()
        self._add_remediation()

        doc.build(
            self.story,
            onFirstPage=self._page_header_footer,
            onLaterPages=self._page_header_footer,
        )
        return path

    # ─────────────────────────────────────────────
    # PAGE DECORATORS
    # ─────────────────────────────────────────────
    def _page_header_footer(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(PALETTE["bg_card"])
        canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
        canvas.setFillColor(PALETTE["accent"])
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(18*mm, h - 9*mm, "WebSentinel Framework  |  Security Assessment Report")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(PALETTE["subtext"])
        canvas.drawRightString(w - 18*mm, h - 9*mm, self.target)

        # Footer bar
        canvas.setFillColor(PALETTE["bg_card"])
        canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(PALETTE["subtext"])
        canvas.drawString(18*mm, 3.5*mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")
        canvas.drawRightString(w - 18*mm, 3.5*mm, f"Page {doc.page}")
        canvas.restoreState()

    # ─────────────────────────────────────────────
    # COVER PAGE
    # ─────────────────────────────────────────────
    def _add_cover(self):
        s = self.story
        s.append(Spacer(1, 30*mm))
        s.append(Paragraph("⚡ WebSentinel Framework", self.styles["cover_title"]))
        s.append(Paragraph("Web Application Security Assessment Report", self.styles["cover_sub"]))
        s.append(Spacer(1, 8*mm))
        s.append(HRFlowable(width="100%", thickness=1, color=PALETTE["accent"]))
        s.append(Spacer(1, 6*mm))

        # Grade + Score box
        grade_color = _grade_color(self.grade)
        data = [
            [Paragraph("TARGET", self.styles["small"]),
             Paragraph("PROFILE", self.styles["small"]),
             Paragraph("SCORE", self.styles["small"]),
             Paragraph("GRADE", self.styles["small"])],
            [Paragraph(f'<font name="Helvetica-Bold" size="10">{self.target}</font>', self.styles["body"]),
             Paragraph(f'<font name="Helvetica-Bold" size="10">{self.scan_profile}</font>', self.styles["body"]),
             Paragraph(f'<font name="Helvetica-Bold" size="18" color="{grade_color.hexval()}">{self.score}/100</font>', self.styles["body"]),
             Paragraph(f'<font name="Helvetica-Bold" size="28" color="{grade_color.hexval()}">{self.grade}</font>', self.styles["body"])],
        ]
        tbl = Table(data, colWidths=["40%", "20%", "20%", "20%"])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PALETTE["bg_card"]),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [PALETTE["bg_card"], PALETTE["bg_card"]]),
            ("TEXTCOLOR", (0, 0), (-1, -1), PALETTE["text"]),
            ("BOX", (0, 0), (-1, -1), 1, PALETTE["accent"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, PALETTE["subtext"]),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        s.append(tbl)
        s.append(Spacer(1, 8*mm))

        # Risk counts row
        risk_data = [[
            Paragraph(f'<font color="{PALETTE["critical"].hexval()}" size="18"><b>{self.risk_dist.get("critical", 0)}</b></font><br/><font size="7">CRITICAL</font>', self.styles["body"]),
            Paragraph(f'<font color="{PALETTE["high"].hexval()}" size="18"><b>{self.risk_dist.get("high", 0)}</b></font><br/><font size="7">HIGH</font>', self.styles["body"]),
            Paragraph(f'<font color="{PALETTE["medium"].hexval()}" size="18"><b>{self.risk_dist.get("medium", 0)}</b></font><br/><font size="7">MEDIUM</font>', self.styles["body"]),
            Paragraph(f'<font color="{PALETTE["low"].hexval()}" size="18"><b>{self.risk_dist.get("low", 0)}</b></font><br/><font size="7">LOW</font>', self.styles["body"]),
            Paragraph(f'<font color="{PALETTE["info"].hexval()}" size="18"><b>{self.risk_dist.get("info", 0)}</b></font><br/><font size="7">INFO</font>', self.styles["body"]),
        ]]
        risk_tbl = Table(risk_data, colWidths=["20%"] * 5)
        risk_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PALETTE["bg_card"]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.5, PALETTE["subtext"]),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        s.append(risk_tbl)
        s.append(Spacer(1, 5*mm))
        s.append(Paragraph(
            f"Scan Date: {datetime.now().strftime('%B %d, %Y')}  |  "
            f"Endpoints Scanned: {len(self.endpoints)}  |  "
            f"Total Findings: {len(self.findings)}",
            self.styles["small"],
        ))
        s.append(PageBreak())

    # ─────────────────────────────────────────────
    # EXECUTIVE SUMMARY
    # ─────────────────────────────────────────────
    def _add_executive_summary(self):
        s = self.story
        s.append(Paragraph("Executive Summary", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))

        grade_color = _grade_color(self.grade)
        criticals = self.risk_dist.get("critical", 0)
        highs = self.risk_dist.get("high", 0)

        summary_text = (
            f"WebSentinel Framework performed a <b>{self.scan_profile}</b> security assessment "
            f"of <b>{self.target}</b> on {datetime.now().strftime('%B %d, %Y')}. "
            f"A total of <b>{len(self.endpoints)}</b> endpoints were discovered and analysed. "
            f"The assessment identified <b>{len(self.findings)}</b> security findings across "
            f"multiple vulnerability categories.<br/><br/>"
            f"The target received a security score of "
            f'<font color="{grade_color.hexval()}"><b>{self.score}/100 (Grade {self.grade})</b></font>. '
        )

        if criticals > 0:
            summary_text += (
                f'<font color="{PALETTE["critical"].hexval()}"><b>{criticals} critical</b></font> and '
                f'<font color="{PALETTE["high"].hexval()}"><b>{highs} high</b></font> severity findings '
                f"require immediate remediation. "
            )
        elif highs > 0:
            summary_text += (
                f'<font color="{PALETTE["high"].hexval()}"><b>{highs} high</b></font> severity findings '
                f"require prompt attention. "
            )
        else:
            summary_text += "No critical or high severity findings were identified. "

        summary_text += (
            "All testing was conducted in a non-destructive manner in accordance with "
            "responsible disclosure principles."
        )

        s.append(Paragraph(summary_text, self.styles["body"]))
        s.append(Spacer(1, 5*mm))

        # Key metrics table
        tech = self.fingerprint
        metrics = [
            ["Metric", "Value"],
            ["Target URL", self.target],
            ["Scan Profile", self.scan_profile],
            ["Security Score", f"{self.score}/100"],
            ["Security Grade", self.grade],
            ["Total Endpoints", str(len(self.endpoints))],
            ["Total Findings", str(len(self.findings))],
            ["Server", tech.get("server") or "Unknown"],
            ["CMS Detected", tech.get("cms") or "None"],
            ["Frameworks", ", ".join(tech.get("frameworks", [])) or "None"],
            ["WAF Detected", self.waf or "None"],
        ]
        tbl = self._make_kv_table(metrics)
        s.append(tbl)
        s.append(PageBreak())

    # ─────────────────────────────────────────────
    # ATTACK SURFACE
    # ─────────────────────────────────────────────
    def _add_attack_surface(self):
        s = self.story
        s.append(Paragraph("Attack Surface Overview", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))

        as_ = self.attack_surface
        by_type = as_.get("by_type", {})

        rows = [["Endpoint Type", "Count", "% of Total"]]
        total = max(as_.get("total_endpoints", 1), 1)
        for ep_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            pct = f"{count / total * 100:.1f}%"
            rows.append([ep_type.capitalize(), str(count), pct])
        rows.append(["TOTAL", str(total), "100%"])

        tbl = Table(rows, colWidths=["40%", "30%", "30%"])
        tbl.setStyle(self._default_table_style(header=True))
        s.append(tbl)
        s.append(Spacer(1, 3*mm))

        params = ", ".join(as_.get("param_names", [])[:15]) or "None"
        s.append(Paragraph(
            f"<b>Endpoints with parameters:</b> {as_.get('endpoints_with_params', 0)}  |  "
            f"<b>Forms detected:</b> {as_.get('total_forms', 0)}  |  "
            f"<b>Unique parameter names:</b> {as_.get('unique_param_names', 0)}",
            self.styles["body"],
        ))
        s.append(Paragraph(f"<b>Parameter names:</b> {params}", self.styles["small"]))

    # ─────────────────────────────────────────────
    # RISK DISTRIBUTION PIE
    # ─────────────────────────────────────────────
    def _add_risk_distribution(self):
        s = self.story
        s.append(Spacer(1, 5*mm))
        s.append(Paragraph("Risk Distribution", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))

        dist = self.risk_dist
        labels = [k.capitalize() for k, v in dist.items() if v > 0]
        values = [v for v in dist.values() if v > 0]

        if values:
            drawing = Drawing(400, 160)
            pie = Pie()
            pie.x = 10
            pie.y = 10
            pie.width = 140
            pie.height = 140
            pie.data = values
            pie.labels = labels
            pie.sideLabels = True
            pie.slices.strokeColor = PALETTE["bg_dark"]
            pie.slices.strokeWidth = 2
            sev_order = ["critical", "high", "medium", "low", "info"]
            active = [k for k, v in dist.items() if v > 0]
            for i, sev in enumerate(active):
                pie.slices[i].fillColor = SEV_COLORS.get(sev, PALETTE["text"])

            drawing.add(pie)

            # Legend
            legend_x = 200
            legend_y = 120
            for i, (sev, val) in enumerate([(k, v) for k, v in dist.items() if v > 0]):
                y = legend_y - i * 20
                drawing.add(Rect(legend_x, y, 12, 12, fillColor=SEV_COLORS.get(sev), strokeWidth=0))
                drawing.add(String(legend_x + 18, y + 2, f"{sev.capitalize()}: {val}", fontSize=9, fillColor=PALETTE["text"]))

            s.append(drawing)
        else:
            s.append(Paragraph("No vulnerabilities found.", self.styles["body"]))

        s.append(Spacer(1, 3*mm))

        # Distribution table
        rows = [["Severity", "Count", "Weight", "Contribution"]]
        import config as cfg
        total_deduct = sum(cfg.SEVERITY_WEIGHTS.get(sev, 0) * count for sev, count in dist.items())
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = dist.get(sev, 0)
            w = cfg.SEVERITY_WEIGHTS.get(sev, 0)
            contrib = f"{w * cnt}"
            rows.append([sev.capitalize(), str(cnt), str(w), contrib])
        tbl = Table(rows, colWidths=["25%", "25%", "25%", "25%"])
        tbl.setStyle(self._severity_table_style(dist))
        s.append(tbl)
        s.append(PageBreak())

    # ─────────────────────────────────────────────
    # TECHNOLOGY FINGERPRINT
    # ─────────────────────────────────────────────
    def _add_tech_fingerprint(self):
        s = self.story
        s.append(Paragraph("Technology Fingerprint", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))
        fp = self.fingerprint
        rows = [
            ["Property", "Detected Value"],
            ["Web Server", fp.get("server") or "Unknown"],
            ["CMS", fp.get("cms") or "Not detected"],
            ["Frameworks", ", ".join(fp.get("frameworks", [])) or "Not detected"],
            ["Languages", ", ".join(fp.get("languages", [])) or "Not detected"],
            ["Technologies", ", ".join(fp.get("technologies", [])) or "Not detected"],
            ["WAF", self.waf or "Not detected"],
        ]
        s.append(self._make_kv_table(rows))

    # ─────────────────────────────────────────────
    # DETAILED FINDINGS
    # ─────────────────────────────────────────────
    def _add_findings(self):
        s = self.story
        s.append(PageBreak())
        s.append(Paragraph("Detailed Findings", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))

        if not self.findings:
            s.append(Paragraph("No vulnerabilities were identified during this assessment.", self.styles["body"]))
            return

        for i, f in enumerate(self.findings, 1):
            sev_color = SEV_COLORS.get(f.severity, PALETTE["text"])
            block = []
            # Finding header
            header = Paragraph(
                f'<font name="Helvetica-Bold" size="11" color="{sev_color.hexval()}">'
                f'[{f.severity.upper()}]</font> '
                f'<font name="Helvetica-Bold" size="11">{i:02d}. {f.title}</font>',
                self.styles["body"],
            )
            block.append(header)
            block.append(HRFlowable(width="100%", thickness=0.5, color=sev_color))
            block.append(Spacer(1, 1*mm))

            # Details grid
            rows = [["Property", "Value"]]
            rows.append(["Type", f.vuln_type])
            rows.append(["Severity", f.severity.capitalize()])
            rows.append(["Confidence", f"{f.confidence}% ({f._confidence_label()})"])
            rows.append(["Exploitability", f.exploitability])
            rows.append(["URL", f.url[:80]])
            if f.parameter:
                rows.append(["Parameter", f.parameter])
            if f.cwe:
                rows.append(["CWE", f.cwe])
            if f.cvss:
                rows.append(["CVSS", str(f.cvss)])
            tbl = self._make_kv_table(rows, header=False)
            block.append(tbl)
            block.append(Spacer(1, 1*mm))
            block.append(Paragraph(f"<b>Description:</b> {f.description}", self.styles["body"]))
            if f.evidence:
                block.append(Paragraph(f"<b>Evidence:</b> {f.evidence[:200]}", self.styles["code"]))
            block.append(Spacer(1, 3*mm))

            s.append(KeepTogether(block))

    # ─────────────────────────────────────────────
    # RISK MATRIX
    # ─────────────────────────────────────────────
    def _add_risk_matrix(self):
        s = self.story
        s.append(PageBreak())
        s.append(Paragraph("Risk Matrix", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))

        matrix = self.risk_matrix_engine.build(self.findings)
        if not matrix:
            s.append(Paragraph("No risk matrix entries.", self.styles["body"]))
            return

        rows = [["#", "Vulnerability", "Severity", "Confidence", "Risk Level"]]
        for i, entry in enumerate(matrix[:40], 1):
            rows.append([
                str(i),
                Paragraph(entry["title"][:55], self.styles["small"]),
                entry["severity"].capitalize(),
                f"{entry['confidence']}%",
                entry.get("risk_level", "MEDIUM"),
            ])

        col_widths = ["5%", "50%", "15%", "15%", "15%"]
        tbl = Table(rows, colWidths=col_widths)
        style = self._default_table_style(header=True)
        # Color severity cells
        for i, entry in enumerate(matrix[:40], 1):
            sev = entry["severity"]
            col = SEV_COLORS.get(sev, PALETTE["text"])
            style.add("TEXTCOLOR", (2, i), (2, i), col)
            style.add("FONTNAME", (2, i), (2, i), "Helvetica-Bold")
        tbl.setStyle(style)
        s.append(tbl)

    # ─────────────────────────────────────────────
    # REMEDIATION SECTION
    # ─────────────────────────────────────────────
    def _add_remediation(self):
        from intelligence.risk_matrix import REMEDIATION_DB
        s = self.story
        s.append(PageBreak())
        s.append(Paragraph("Remediation Guidance", self.styles["h1"]))
        s.append(HRFlowable(width="100%", thickness=0.5, color=PALETTE["accent"]))
        s.append(Spacer(1, 3*mm))

        seen = set()
        for f in self.findings:
            if f.vuln_type in seen:
                continue
            seen.add(f.vuln_type)
            guidance = REMEDIATION_DB.get(f.vuln_type, "Consult OWASP guidelines.")
            sev_color = SEV_COLORS.get(f.severity, PALETTE["text"])
            s.append(Paragraph(
                f'<font name="Helvetica-Bold" color="{sev_color.hexval()}">{f.vuln_type}</font>',
                self.styles["h2"],
            ))
            s.append(Paragraph(guidance, self.styles["body"]))
            s.append(Spacer(1, 2*mm))

    # ─────────────────────────────────────────────
    # HELPER TABLE BUILDERS
    # ─────────────────────────────────────────────
    def _make_kv_table(self, rows, header=True):
        tbl = Table(rows, colWidths=["35%", "65%"])
        style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PALETTE["accent"] if header else PALETTE["bg_card"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), PALETTE["bg_dark"] if header else PALETTE["text"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PALETTE["bg_card"], PALETTE["bg_dark"]]),
            ("TEXTCOLOR", (0, 1), (-1, -1), PALETTE["text"]),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 1), (0, -1), PALETTE["subtext"]),
            ("BOX", (0, 0), (-1, -1), 0.5, PALETTE["subtext"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, PALETTE["bg_card"]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ])
        tbl.setStyle(style)
        return tbl

    def _default_table_style(self, header=True):
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PALETTE["accent"] if header else PALETTE["bg_card"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), PALETTE["bg_dark"] if header else PALETTE["text"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PALETTE["bg_card"], PALETTE["bg_dark"]]),
            ("TEXTCOLOR", (0, 1), (-1, -1), PALETTE["text"]),
            ("BOX", (0, 0), (-1, -1), 0.5, PALETTE["subtext"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, PALETTE["bg_card"]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ])

    def _severity_table_style(self, dist):
        style = self._default_table_style(header=True)
        sev_list = [k for k, v in dist.items() if v > 0]
        for i, sev in enumerate(["critical", "high", "medium", "low", "info"], 1):
            col = SEV_COLORS.get(sev, PALETTE["text"])
            style.add("TEXTCOLOR", (0, i), (0, i), col)
            style.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
        return style
