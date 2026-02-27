#!/usr/bin/env python3
"""
WebSentinel Framework - Main Entry Point
Advanced Web Application Security Assessment Tool
"""

import sys
import os
import argparse
import time
import warnings
import urllib3

# Suppress SSL warnings for non-destructive scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from utils.logger import Logger
from utils.helpers import elapsed_str, extract_base_url, deduplicate_findings
from core.request_engine import RequestEngine
from core.crawler import CrawlerEngine
from core.response_analyzer import ResponseAnalyzer
from core.diff_engine import DiffEngine
from core.scorer import ScoringEngine, Finding
from intelligence.fingerprint import FingerprintEngine
from intelligence.endpoint_classifier import EndpointClassifier
from reports.json_report import JSONReporter
from reports.pdf_report import PDFReporter

# ─────────────────────────────────────────────
# IMPORT ALL MODULES
# ─────────────────────────────────────────────
from modules.injection_modules import (
    SQLInjectionModule, NoSQLInjectionModule,
    CommandInjectionModule, LDAPInjectionModule, XMLInjectionModule
)
from modules.xss_modules import (
    XSSModule, StoredXSSModule, DOMXSSModule, CSRFModule
)
from modules.access_modules import (
    IDORModule, BrokenAuthModule, SessionAnalysisModule, BrokenAccessControlModule
)
from modules.network_modules import (
    SSRFModule, OpenRedirectModule, CORSModule, SecurityHeadersModule,
    ClickjackingModule, DirectoryListingModule, HostHeaderInjectionModule,
    RateLimitingModule
)
from modules.file_modules import (
    LFIModule, PathTraversalModule, RFIModule, FileUploadModule,
    InfoDisclosureModule, SensitiveFileModule
)
from modules.misc_modules import (
    APIMisconfigModule, MassAssignmentModule, HardcodedCredentialsModule,
    WeakCryptoModule, SubdomainTakeoverModule, CachePoisoningModule,
    InsecureDeserializationModule
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websentinel",
        description="WebSentinel Framework — Advanced Web Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u https://example.com -p balanced
  python main.py -u https://example.com -p deep-safe -d 4 --cookies "session=abc123"
  python main.py -u https://example.com -p passive --no-robots --rps 1
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument(
        "-p", "--profile",
        choices=["passive", "balanced", "deep-safe"],
        default="balanced",
        help="Scan profile (default: balanced)",
    )
    parser.add_argument("-d", "--depth", type=int, default=None,
                        help="Crawl depth (overrides profile default)")
    parser.add_argument("--cookies", default="",
                        help='Authentication cookies, e.g. "session=abc; token=xyz"')
    parser.add_argument("--rps", type=float, default=None,
                        help="Max requests per second (overrides profile default)")
    parser.add_argument("--delay", type=float, default=None,
                        help="Fixed delay between requests in seconds")
    parser.add_argument("--timeout", type=int, default=config.DEFAULT_TIMEOUT,
                        help=f"Request timeout in seconds (default: {config.DEFAULT_TIMEOUT})")
    parser.add_argument("--no-robots", action="store_true",
                        help="Ignore robots.txt restrictions")
    parser.add_argument("--output-dir", default=config.OUTPUT_DIR,
                        help=f"Output directory (default: {config.OUTPUT_DIR})")
    parser.add_argument("--json-only", action="store_true",
                        help="Generate JSON report only (skip PDF)")
    parser.add_argument("--no-pdf", action="store_true",
                        help="Skip PDF report generation")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose debug output")
    return parser


def parse_cookies(cookie_str: str) -> dict:
    """Parse a cookie string into a dict."""
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def get_scan_modules(engine, analyzer, diff, profile, logger):
    """Instantiate all scanning modules."""
    args = (engine, analyzer, diff, profile, logger)
    return [
        # Header & Cookie analysis
        SecurityHeadersModule(*args),
        ClickjackingModule(*args),
        CORSModule(*args),
        # Information Disclosure
        InfoDisclosureModule(*args),
        SensitiveFileModule(*args),
        HardcodedCredentialsModule(*args),
        WeakCryptoModule(*args),
        # Injection
        SQLInjectionModule(*args),
        NoSQLInjectionModule(*args),
        CommandInjectionModule(*args),
        LDAPInjectionModule(*args),
        XMLInjectionModule(*args),
        # XSS Family
        XSSModule(*args),
        StoredXSSModule(*args),
        DOMXSSModule(*args),
        CSRFModule(*args),
        # Access Control
        IDORModule(*args),
        BrokenAuthModule(*args),
        SessionAnalysisModule(*args),
        BrokenAccessControlModule(*args),
        # Network
        SSRFModule(*args),
        OpenRedirectModule(*args),
        DirectoryListingModule(*args),
        HostHeaderInjectionModule(*args),
        RateLimitingModule(*args),
        # File
        LFIModule(*args),
        PathTraversalModule(*args),
        RFIModule(*args),
        FileUploadModule(*args),
        # Misc
        APIMisconfigModule(*args),
        MassAssignmentModule(*args),
        SubdomainTakeoverModule(*args),
        CachePoisoningModule(*args),
        InsecureDeserializationModule(*args),
    ]


def confirm_legal(logger: Logger, target: str) -> bool:
    """Show legal disclaimer and require explicit consent."""
    print(config.LEGAL_DISCLAIMER)
    print(f"  Target: {target}\n")
    try:
        answer = input(
            "  Do you have EXPLICIT authorization to scan this target? [yes/NO]: "
        ).strip().lower()
        if answer not in ("yes", "y"):
            logger.error("Authorization not confirmed. Aborting.")
            return False
        return True
    except (KeyboardInterrupt, EOFError):
        print()
        logger.error("Cancelled by user.")
        return False


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    logger = Logger(verbose=args.verbose)
    logger.banner()

    # ─── Legal Confirmation ───────────────────────────────────────────────
    if not confirm_legal(logger, args.url):
        sys.exit(1)

    start_time = time.time()
    logger.separator()

    # ─── Load Profile ─────────────────────────────────────────────────────
    profile_cfg = dict(config.SCAN_PROFILES[args.profile])
    if args.depth is not None:
        profile_cfg["max_depth"] = args.depth
    if args.rps is not None:
        profile_cfg["max_rps"] = args.rps

    delay = args.delay or profile_cfg["delay_range"][0]
    max_rps = profile_cfg["max_rps"]
    cookies = parse_cookies(args.cookies)

    logger.info(f"Target       : {args.url}")
    logger.info(f"Profile      : {args.profile} — {profile_cfg['description']}")
    logger.info(f"Crawl Depth  : {profile_cfg['max_depth']}")
    logger.info(f"Rate Limit   : {max_rps} req/s  |  Delay: {delay:.1f}s")
    logger.info(f"Auth Cookies : {len(cookies)} cookies provided")
    logger.separator()

    # ─── Stage 1: Initialize Engines ──────────────────────────────────────
    logger.stage("Initializing Engines")

    engine = RequestEngine(
        delay=delay,
        max_rps=max_rps,
        timeout=args.timeout,
        cookies=cookies,
        random_delay=True,
        delay_range=profile_cfg["delay_range"],
    )
    analyzer = ResponseAnalyzer()
    diff_engine = DiffEngine()
    fp_engine = FingerprintEngine()

    # ─── Stage 2: Fingerprinting ──────────────────────────────────────────
    logger.stage("Technology Fingerprinting")

    root_result = engine.get(args.url)
    if not root_result.ok:
        logger.error(f"Cannot reach target: {root_result.error}")
        sys.exit(2)

    fingerprint = fp_engine.fingerprint(
        headers=root_result.headers,
        body=root_result.body,
        cookies=dict(engine.session.cookies),
    )
    waf = fp_engine.detect_waf(root_result.headers, root_result.body)

    fp_dict = fingerprint.to_dict()
    logger.success(f"Server      : {fp_dict.get('server') or 'Unknown'}")
    logger.success(f"CMS         : {fp_dict.get('cms') or 'Not detected'}")
    logger.success(f"Frameworks  : {', '.join(fp_dict.get('frameworks', [])) or 'None'}")
    logger.success(f"Languages   : {', '.join(fp_dict.get('languages', [])) or 'None'}")
    logger.info   (f"WAF         : {waf or 'Not detected'}")

    # ─── Stage 3: Crawling ────────────────────────────────────────────────
    logger.stage("Web Crawling & Endpoint Discovery")

    crawler = CrawlerEngine(
        base_url=args.url,
        engine=engine,
        max_depth=profile_cfg["max_depth"],
        respect_robots=not args.no_robots,
        logger=logger,
    )
    endpoints = crawler.crawl()
    crawler_stats = crawler.get_stats()

    logger.success(f"Endpoints discovered : {crawler_stats['total_endpoints']}")
    logger.info   (f"With parameters      : {crawler_stats['endpoints_with_params']}")
    logger.info   (f"With forms           : {crawler_stats['endpoints_with_forms']}")

    # ─── Stage 4: Endpoint Classification ────────────────────────────────
    logger.stage("Endpoint Classification & Prioritization")

    classifier = EndpointClassifier()
    classified = classifier.classify_all(endpoints)
    attack_surface = classifier.get_attack_surface_summary(endpoints)

    type_summary = attack_surface.get("by_type", {})
    for ep_type, count in sorted(type_summary.items(), key=lambda x: x[1], reverse=True):
        logger.info(f"  {ep_type:<12}: {count}")

    # ─── Stage 5: Vulnerability Scanning ─────────────────────────────────
    logger.stage("Vulnerability Scanning")

    all_findings: list[Finding] = []
    modules = get_scan_modules(engine, analyzer, diff_engine, profile_cfg, logger)

    total_endpoints = len(classified)
    for ep_idx, ep_info in enumerate(classified, 1):
        endpoint = ep_info["endpoint"]
        rec_modules = ep_info["modules"]
        logger.progress(ep_idx, total_endpoints, f"→ {endpoint.url[:55]}")

        for mod in modules:
            if mod.MODULE_NAME not in rec_modules:
                continue
            try:
                mod.findings.clear()
                findings = mod.run(endpoint)
                all_findings.extend(findings)
            except Exception as e:
                logger.debug(f"Module {mod.MODULE_NAME} error: {e}")

    # Deduplicate
    raw_findings = [Finding(**{
        "vuln_type": f.vuln_type, "severity": f.severity, "title": f.title,
        "url": f.url, "description": f.description, "evidence": f.evidence,
        "parameter": f.parameter, "confidence": f.confidence,
        "remediation": f.remediation, "cwe": f.cwe, "cvss": f.cvss,
        "exploitability": f.exploitability,
    }) for f in all_findings]

    # Simple dedup by type+url+param
    seen = set()
    unique_findings = []
    for f in raw_findings:
        key = (f.vuln_type, f.url, f.parameter)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # ─── Stage 6: Scoring ─────────────────────────────────────────────────
    logger.stage("Risk Scoring & Grade Calculation")

    scorer = ScoringEngine(unique_findings)
    score = scorer.calculate_score()
    grade = scorer.get_grade(score)
    risk_dist = scorer.risk_distribution()

    logger.success(f"Security Score  : {score}/100")
    logger.success(f"Security Grade  : {grade}")
    logger.info   (f"Findings Total  : {len(unique_findings)}")
    for sev, cnt in risk_dist.items():
        if cnt > 0:
            logger.info(f"  {sev:<10}: {cnt}")

    # ─── Stage 7: Report Generation ───────────────────────────────────────
    logger.stage("Report Generation")

    os.makedirs(args.output_dir, exist_ok=True)

    # JSON
    json_path = os.path.join(args.output_dir, config.JSON_REPORT_NAME)
    json_reporter = JSONReporter(
        target=args.url,
        scan_profile=args.profile,
        endpoints=endpoints,
        findings=unique_findings,
        fingerprint=fp_dict,
        attack_surface=attack_surface,
        waf=waf,
    )
    json_reporter.save(json_path)
    logger.success(f"JSON report saved : {json_path}")

    # PDF
    if not args.json_only and not args.no_pdf:
        try:
            pdf_path = os.path.join(args.output_dir, config.PDF_REPORT_NAME)
            pdf_reporter = PDFReporter(
                target=args.url,
                scan_profile=args.profile,
                endpoints=endpoints,
                findings=unique_findings,
                fingerprint=fp_dict,
                attack_surface=attack_surface,
                waf=waf,
            )
            pdf_reporter.generate(pdf_path)
            logger.success(f"PDF report saved  : {pdf_path}")
        except Exception as e:
            logger.warning(f"PDF generation failed: {e}")

    # ─── Final Summary ────────────────────────────────────────────────────
    elapsed = time.time() - start_time

    from colorama import Fore, Style
    grade_colors = {
        "A": Fore.GREEN, "B": Fore.GREEN,
        "C": Fore.YELLOW, "D": Fore.YELLOW, "F": Fore.RED,
    }
    gc = grade_colors.get(grade, Fore.WHITE)

    summary_lines = [
        f"Target          : {args.url}",
        f"Profile         : {args.profile}",
        f"Scan Duration   : {elapsed_str(elapsed)}",
        f"Requests Made   : {engine.request_count}",
        "",
        f"Endpoints       : {len(endpoints)}",
        f"Total Findings  : {len(unique_findings)}",
        "",
        f"  Critical      : {risk_dist.get('critical', 0)}",
        f"  High          : {risk_dist.get('high', 0)}",
        f"  Medium        : {risk_dist.get('medium', 0)}",
        f"  Low           : {risk_dist.get('low', 0)}",
        f"  Info          : {risk_dist.get('info', 0)}",
        "",
        f"Security Score  : {score}/100",
        f"Security Grade  : {gc}{Style.BRIGHT}{grade}{Style.RESET_ALL}",
    ]

    logger.summary_box("⚡  WEBSENTINEL SCAN COMPLETE", summary_lines)
    engine.close()


if __name__ == "__main__":
    main()
