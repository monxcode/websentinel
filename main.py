#!/usr/bin/env python3
"""
WebSentinel Framework - Main Entry Point
Advanced Web Application Security Assessment Tool

Authentication support:
  --login "username=admin&password=secret"  → Auto form-based login
  --cookies "session=abc123"               → Direct cookie injection
  Both modes can be combined for maximum access.
"""

import sys
import os
import argparse
import time
import warnings
import urllib3
from urllib.parse import urlparse

# Suppress SSL warnings for non-destructive scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from utils.logger import Logger
from utils.helpers import elapsed_str, extract_base_url
from core.request_engine import RequestEngine
from core.auth_handler import AuthHandler, parse_cookie_string
from core.payload_loader import PayloadLoader, validate_payload_file
from core.crawler import CrawlerEngine
from core.response_analyzer import ResponseAnalyzer
from core.diff_engine import DiffEngine
from core.scorer import ScoringEngine, Finding
from intelligence.fingerprint import FingerprintEngine
from intelligence.endpoint_classifier import EndpointClassifier
from reports.json_report import JSONReporter
from reports.pdf_report import PDFReporter

# ─────────────────────────────────────────────
# IMPORT ALL VULNERABILITY MODULES
# ─────────────────────────────────────────────
from modules.injection_modules import (
    SQLInjectionModule,
    NoSQLInjectionModule,
    CommandInjectionModule,
    LDAPInjectionModule,
    XMLInjectionModule,
)
from modules.xss_modules import (
    XSSModule,
    StoredXSSModule,
    DOMXSSModule,
    CSRFModule,
)
from modules.access_modules import (
    IDORModule,
    BrokenAuthModule,
    SessionAnalysisModule,
    BrokenAccessControlModule,
)
from modules.network_modules import (
    SSRFModule,
    OpenRedirectModule,
    CORSModule,
    SecurityHeadersModule,
    ClickjackingModule,
    DirectoryListingModule,
    HostHeaderInjectionModule,
    RateLimitingModule,
)
from modules.file_modules import (
    LFIModule,
    PathTraversalModule,
    RFIModule,
    FileUploadModule,
    InfoDisclosureModule,
    SensitiveFileModule,
)
from modules.misc_modules import (
    APIMisconfigModule,
    MassAssignmentModule,
    HardcodedCredentialsModule,
    WeakCryptoModule,
    SubdomainTakeoverModule,
    CachePoisoningModule,
    InsecureDeserializationModule,
)


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websentinel",
        description="WebSentinel Framework — Advanced Web Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Basic scan:
    python main.py -u https://example.com -p balanced

  Auto-login then scan:
    python main.py -u https://example.com/login -p balanced \\
      --login "username=admin&password=admin123"

  Login with custom field names:
    python main.py -u https://example.com/login -p balanced \\
      --login "email=admin@site.com&passwd=secret" \\
      --scan-url https://example.com

  Session cookie (no login form needed):
    python main.py -u https://example.com -p balanced \\
      --cookies "session=abc123"

  Cookie with no token requirement:
    python main.py -u https://example.com -p deep-safe \\
      --cookies "PHPSESSID=xyz456; user_id=1"

  Login + extra cookies combined:
    python main.py -u https://example.com/login -p balanced \\
      --login "username=admin&password=secret" \\
      --cookies "remember_me=1; theme=dark"

  Production-safe slow scan:
    python main.py -u https://example.com -p passive \\
      --rps 0.5 --delay 3 --timeout 30

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """,
    )

    # ── Target ──────────────────────────────────────────────────────────
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL. When --login is used, this should be the login page URL.",
    )
    target_group.add_argument(
        "--scan-url",
        default=None,
        metavar="URL",
        help=(
            "URL to crawl/scan after login. If omitted, scan starts from the "
            "base domain of --url (or post-login redirect URL)."
        ),
    )

    # ── Scan Profile ────────────────────────────────────────────────────
    scan_group = parser.add_argument_group("Scan Settings")
    scan_group.add_argument(
        "-p",
        "--profile",
        choices=["passive", "balanced", "deep-safe"],
        default="balanced",
        help="Scan profile: passive / balanced / deep-safe  (default: balanced)",
    )
    scan_group.add_argument(
        "-d",
        "--depth",
        type=int,
        default=None,
        help="Crawl depth — overrides profile default.",
    )
    scan_group.add_argument(
        "--no-robots",
        action="store_true",
        help="Ignore robots.txt disallow rules.",
    )
    scan_group.add_argument(
        "--payloads",
        default=None,
        metavar="FILE",
        help=(
            "Path to a custom payload file (.txt / .json / .csv). "
            "Payloads are merged with built-in lists before scanning begins. "
            "Examples: --payloads payloads/sqli.txt  --payloads custom.json"
        ),
    )
    scan_group.add_argument(
        "--payloads-append",
        action="store_true",
        help=(
            "Append custom payloads AFTER built-in payloads instead of "
            "prepending them. Default: custom payloads are tested first."
        ),
    )

    # ── Authentication ───────────────────────────────────────────────────
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--login",
        default="",
        metavar="CREDENTIALS",
        help=(
            'Form-based login credentials. Format: "username=admin&password=secret"\n'
            "WebSentinel auto-discovers the login form, injects CSRF tokens,\n"
            "and captures the resulting session cookies.\n"
            'Example: --login "email=admin@example.com&password=Admin@123"'
        ),
    )
    auth_group.add_argument(
        "--cookies",
        default="",
        metavar="COOKIE_STRING",
        help=(
            "Pre-set session cookies. No token required.\n"
            'Format: "name=value; name2=value2"\n'
            "Examples:\n"
            '  --cookies "session=abc123"\n'
            '  --cookies "PHPSESSID=abc; csrf_token=xyz"\n'
            '  --cookies "session=xyz456"   (works without any other token)'
        ),
    )
    auth_group.add_argument(
        "--auth-verify",
        action="store_true",
        help="Verify session is authenticated before scanning starts.",
    )

    # ── Request Engine ───────────────────────────────────────────────────
    req_group = parser.add_argument_group("Request Engine")
    req_group.add_argument(
        "--rps",
        type=float,
        default=None,
        help="Max requests per second  (overrides profile default).",
    )
    req_group.add_argument(
        "--delay",
        type=float,
        default=None,
        help="Fixed delay in seconds between requests.",
    )
    req_group.add_argument(
        "--timeout",
        type=int,
        default=config.DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds  (default: {config.DEFAULT_TIMEOUT}).",
    )

    # ── Output ───────────────────────────────────────────────────────────
    out_group = parser.add_argument_group("Output")
    out_group.add_argument(
        "--output-dir",
        default=config.OUTPUT_DIR,
        help=f"Directory for reports  (default: {config.OUTPUT_DIR}).",
    )
    out_group.add_argument(
        "--json-only",
        action="store_true",
        help="Generate JSON report only — skip PDF.",
    )
    out_group.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF report generation.",
    )
    out_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose / debug output.",
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────


def confirm_legal(logger: Logger, target: str) -> bool:
    """Show legal disclaimer and require explicit typed consent."""
    print(config.LEGAL_DISCLAIMER)
    print(f"  Target: {target}\n")
    try:
        answer = (
            input(
                "  Do you have EXPLICIT authorization to scan this target? [yes/NO]: "
            )
            .strip()
            .lower()
        )
        if answer not in ("yes", "y"):
            logger.error("Authorization not confirmed. Aborting.")
            return False
        return True
    except (KeyboardInterrupt, EOFError):
        print()
        logger.error("Cancelled by user.")
        return False


def resolve_scan_url(login_url: str, scan_url: str, post_login_url: str) -> str:
    """
    Determine the URL to begin crawling from.
    Priority: --scan-url > post-login redirect URL > base domain of --url
    """
    if scan_url:
        return scan_url
    parsed_post = urlparse(post_login_url)
    parsed_login = urlparse(login_url)
    # If post-login redirected to a different path, scan from base domain
    if parsed_post.netloc and parsed_post.netloc == parsed_login.netloc:
        return f"{parsed_post.scheme}://{parsed_post.netloc}"
    return f"{parsed_login.scheme}://{parsed_login.netloc}"


def get_scan_modules(engine, analyzer, diff, profile, logger):
    """Instantiate all scanning modules."""
    args = (engine, analyzer, diff, profile, logger)
    return [
        SecurityHeadersModule(*args),
        ClickjackingModule(*args),
        CORSModule(*args),
        InfoDisclosureModule(*args),
        SensitiveFileModule(*args),
        HardcodedCredentialsModule(*args),
        WeakCryptoModule(*args),
        SQLInjectionModule(*args),
        NoSQLInjectionModule(*args),
        CommandInjectionModule(*args),
        LDAPInjectionModule(*args),
        XMLInjectionModule(*args),
        XSSModule(*args),
        StoredXSSModule(*args),
        DOMXSSModule(*args),
        CSRFModule(*args),
        IDORModule(*args),
        BrokenAuthModule(*args),
        SessionAnalysisModule(*args),
        BrokenAccessControlModule(*args),
        SSRFModule(*args),
        OpenRedirectModule(*args),
        DirectoryListingModule(*args),
        HostHeaderInjectionModule(*args),
        RateLimitingModule(*args),
        LFIModule(*args),
        PathTraversalModule(*args),
        RFIModule(*args),
        FileUploadModule(*args),
        APIMisconfigModule(*args),
        MassAssignmentModule(*args),
        SubdomainTakeoverModule(*args),
        CachePoisoningModule(*args),
        InsecureDeserializationModule(*args),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    logger = Logger(verbose=args.verbose)
    logger.banner()

    # ── Legal Confirmation ────────────────────────────────────────────────
    if not confirm_legal(logger, args.url):
        sys.exit(1)

    start_time = time.time()
    logger.separator()

    # ── Load Profile ──────────────────────────────────────────────────────
    profile_cfg = dict(config.SCAN_PROFILES[args.profile])
    if args.depth is not None:
        profile_cfg["max_depth"] = args.depth
    if args.rps is not None:
        profile_cfg["max_rps"] = args.rps

    delay = args.delay or profile_cfg["delay_range"][0]
    max_rps = profile_cfg["max_rps"]

    # Parse any pre-provided cookies (--cookies flag)
    preset_cookies = parse_cookie_string(args.cookies)

    logger.info(f"Target       : {args.url}")
    logger.info(f"Profile      : {args.profile} — {profile_cfg['description']}")
    logger.info(f"Crawl Depth  : {profile_cfg['max_depth']}")
    logger.info(f"Rate Limit   : {max_rps} req/s  |  Delay: {delay:.1f}s")
    if preset_cookies:
        logger.info(
            f"Preset Cookies: {len(preset_cookies)} → {list(preset_cookies.keys())}"
        )
    if args.login:
        logger.info(f"Auth Mode    : Form-based login (auto-discover form)")
    elif preset_cookies:
        logger.info(f"Auth Mode    : Cookie session (no token required)")
    else:
        logger.info(f"Auth Mode    : Unauthenticated")
    if args.payloads:
        logger.info(f"Custom Payloads: {pathlib.Path(args.payloads).name}")
    logger.separator()

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 1: Initialize Request Engine
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Initializing Engines")

    engine = RequestEngine(
        delay=delay,
        max_rps=max_rps,
        timeout=args.timeout,
        cookies=preset_cookies,  # cookie-only session — no token required
        random_delay=True,
        delay_range=profile_cfg["delay_range"],
    )
    analyzer = ResponseAnalyzer()
    diff_engine = DiffEngine()
    fp_engine = FingerprintEngine()

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 1.5: Custom Payload Injection
    # ─────────────────────────────────────────────────────────────────────
    if args.payloads:
        logger.stage("Loading Custom Payloads")
        ok, msg = validate_payload_file(args.payloads)
        if not ok:
            logger.error(f"Payload file error: {msg}")
            sys.exit(3)
        try:
            payload_loader = PayloadLoader(config, logger=logger)
            payload_result = payload_loader.load_and_inject(
                args.payloads,
                prepend=not args.payloads_append,
            )
            logger.success(payload_result.summary())
            if payload_result.warnings:
                for w in payload_result.warnings:
                    logger.warning(f"  {w}")
            logger.info(
                f"Injection mode : "
                f"{'prepend (custom first)' if not args.payloads_append else 'append (built-in first)'}"
            )
        except (FileNotFoundError, ValueError) as e:
            logger.error(f"Failed to load payload file: {e}")
            sys.exit(3)
        logger.separator()

    auth_result = None
    scan_start_url = args.url

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 2: Authentication
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Authentication")

    auth_handler = AuthHandler(
        session=engine.session,
        timeout=args.timeout,
        logger=logger,
    )

    if args.login:
        # ── Form-Based Login ─────────────────────────────────────────────
        logger.info(f"Attempting form-based login → {args.url}")
        auth_result = auth_handler.login(
            login_url=args.url,
            credentials=args.login,
            extra_cookies=preset_cookies,
        )

        if auth_result.success:
            logger.success(f"Login successful!")
            logger.success(f"Post-login URL   : {auth_result.post_login_url}")
            logger.success(f"Session cookies  : {list(auth_result.cookies.keys())}")
            if auth_result.csrf_token:
                logger.info(f"CSRF token       : captured automatically")
            # Apply all auth cookies to engine session
            engine.apply_cookies(auth_result.cookies)
            # Resolve scan start URL
            scan_start_url = resolve_scan_url(
                args.url, args.scan_url, auth_result.post_login_url
            )
            logger.info(f"Scan will start from: {scan_start_url}")
        else:
            logger.warning(f"Login may have failed: {auth_result.failure_reason}")
            logger.warning("Continuing scan with available cookies (if any)")
            scan_start_url = resolve_scan_url(args.url, args.scan_url, args.url)

    elif preset_cookies:
        # ── Cookie-Only Session ──────────────────────────────────────────
        logger.info(f"Applying session cookies — no form login, no token required")
        auth_result = auth_handler.apply_cookies(
            cookies=preset_cookies,
            target_url=args.url,
        )

        if auth_result.success:
            logger.success(f"Session cookies applied successfully")
            logger.success(f"Active cookies: {list(auth_result.cookies.keys())}")
        else:
            logger.warning(f"Cookie session check: {auth_result.failure_reason}")
            logger.warning("Continuing scan with provided cookies anyway")
        scan_start_url = args.scan_url or args.url

    else:
        # ── Unauthenticated ──────────────────────────────────────────────
        logger.info("No authentication provided — scanning as unauthenticated user")
        scan_start_url = args.scan_url or args.url

    # ── Optional: Verify session before scanning ─────────────────────────
    if args.auth_verify and (args.login or preset_cookies):
        logger.info(f"Verifying session → {scan_start_url}")
        verified, reason = auth_handler.verify_session(scan_start_url)
        if verified:
            logger.success(f"Session verified: {reason}")
        else:
            logger.warning(f"Session verification: {reason}")

    # Log active session summary
    active_cookies = engine.get_active_cookies()
    if active_cookies:
        logger.info(
            f"Active session cookies ({len(active_cookies)}): "
            f"{list(active_cookies.keys())}"
        )
    logger.separator()

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 3: Technology Fingerprinting
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Technology Fingerprinting")

    root_result = engine.get(scan_start_url)
    if not root_result.ok:
        logger.error(f"Cannot reach scan target: {root_result.error}")
        logger.error(f"URL attempted: {scan_start_url}")
        sys.exit(2)

    fingerprint = fp_engine.fingerprint(
        headers=root_result.headers,
        body=root_result.body,
        cookies=engine.get_active_cookies(),
    )
    waf = fp_engine.detect_waf(root_result.headers, root_result.body)

    fp_dict = fingerprint.to_dict()
    logger.success(f"Server      : {fp_dict.get('server') or 'Unknown'}")
    logger.success(f"CMS         : {fp_dict.get('cms') or 'Not detected'}")
    logger.success(
        f"Frameworks  : {', '.join(fp_dict.get('frameworks', [])) or 'None'}"
    )
    logger.success(f"Languages   : {', '.join(fp_dict.get('languages', [])) or 'None'}")
    logger.info(f"WAF         : {waf or 'Not detected'}")

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 4: Web Crawling
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Web Crawling & Endpoint Discovery")

    crawler = CrawlerEngine(
        base_url=scan_start_url,
        engine=engine,
        max_depth=profile_cfg["max_depth"],
        respect_robots=not args.no_robots,
        logger=logger,
    )
    endpoints = crawler.crawl()
    crawler_stats = crawler.get_stats()

    logger.success(f"Endpoints discovered : {crawler_stats['total_endpoints']}")
    logger.info(f"With parameters      : {crawler_stats['endpoints_with_params']}")
    logger.info(f"With forms           : {crawler_stats['endpoints_with_forms']}")

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 5: Endpoint Classification
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Endpoint Classification & Prioritization")

    classifier = EndpointClassifier()
    classified = classifier.classify_all(endpoints)
    attack_surface = classifier.get_attack_surface_summary(endpoints)

    type_summary = attack_surface.get("by_type", {})
    for ep_type, count in sorted(
        type_summary.items(), key=lambda x: x[1], reverse=True
    ):
        logger.info(f"  {ep_type:<12}: {count}")

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 6: Vulnerability Scanning
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Vulnerability Scanning")

    all_findings: list = []
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

    # ── Deduplicate Findings ─────────────────────────────────────────────
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.vuln_type, f.url, f.parameter)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 7: Risk Scoring
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Risk Scoring & Grade Calculation")

    scorer = ScoringEngine(unique_findings)
    score = scorer.calculate_score()
    grade = scorer.get_grade(score)
    risk_dist = scorer.risk_distribution()

    logger.success(f"Security Score  : {score}/100")
    logger.success(f"Security Grade  : {grade}")
    logger.info(f"Findings Total  : {len(unique_findings)}")
    for sev, cnt in risk_dist.items():
        if cnt > 0:
            logger.info(f"  {sev:<10}: {cnt}")

    # ─────────────────────────────────────────────────────────────────────
    # STAGE 8: Report Generation
    # ─────────────────────────────────────────────────────────────────────
    logger.stage("Report Generation")

    os.makedirs(args.output_dir, exist_ok=True)

    # Build auth summary for reports
    auth_summary = (
        auth_result.to_dict()
        if auth_result
        else {
            "success": False,
            "auth_method": "none",
            "session_cookies": [],
        }
    )

    # JSON Report
    json_path = os.path.join(args.output_dir, config.JSON_REPORT_NAME)
    json_reporter = JSONReporter(
        target=scan_start_url,
        scan_profile=args.profile,
        endpoints=endpoints,
        findings=unique_findings,
        fingerprint=fp_dict,
        attack_surface=attack_surface,
        waf=waf,
        auth_summary=auth_summary,
    )
    json_reporter.save(json_path)
    logger.success(f"JSON report saved : {json_path}")

    # PDF Report
    if not args.json_only and not args.no_pdf:
        try:
            pdf_path = os.path.join(args.output_dir, config.PDF_REPORT_NAME)
            pdf_reporter = PDFReporter(
                target=scan_start_url,
                scan_profile=args.profile,
                endpoints=endpoints,
                findings=unique_findings,
                fingerprint=fp_dict,
                attack_surface=attack_surface,
                waf=waf,
                auth_summary=auth_summary,
            )
            pdf_reporter.generate(pdf_path)
            logger.success(f"PDF report saved  : {pdf_path}")
        except Exception as e:
            logger.warning(f"PDF generation failed: {e}")

    # ── Final Summary Box ─────────────────────────────────────────────────
    elapsed = time.time() - start_time

    from colorama import Fore, Style

    grade_colors = {
        "A": Fore.GREEN,
        "B": Fore.GREEN,
        "C": Fore.YELLOW,
        "D": Fore.YELLOW,
        "F": Fore.RED,
    }
    gc = grade_colors.get(grade, Fore.WHITE)

    auth_mode = (
        "Form Login" if args.login else ("Cookie Session" if preset_cookies else "None")
    )
    payload_info = (
        f"Yes — {pathlib.Path(args.payloads).name}"
        if args.payloads
        else "No (built-in only)"
    )

    summary_lines = [
        f"Target          : {scan_start_url}",
        f"Profile         : {args.profile}",
        f"Auth Mode       : {auth_mode}",
        f"Custom Payloads : {payload_info}",
        f"Session Cookies : {len(engine.get_active_cookies())}",
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
