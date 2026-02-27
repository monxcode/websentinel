"""
WebSentinel Framework - Helpers Utility
URL normalization, deduplication, and general utility functions.
"""

import re
import time
import hashlib
import urllib.parse
from typing import Optional, Set, Dict, List, Tuple
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse


def normalize_url(url: str) -> str:
    """Normalize a URL by sorting query params and removing fragments."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params.items()), doseq=True)
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            sorted_query,
            "",  # strip fragment
        ))
        return normalized
    except Exception:
        return url


def url_fingerprint(url: str) -> str:
    """Generate a structural fingerprint for deduplication (ignores param values)."""
    try:
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())
        key = f"{parsed.netloc}{parsed.path}?{'&'.join(params)}"
        return hashlib.md5(key.encode()).hexdigest()
    except Exception:
        return hashlib.md5(url.encode()).hexdigest()


def is_same_domain(url: str, base_url: str) -> bool:
    """Check if a URL belongs to the same domain as the base URL."""
    try:
        url_host = urlparse(url).netloc.lower()
        base_host = urlparse(base_url).netloc.lower()
        # Strip www prefix for comparison
        url_host = url_host.lstrip("www.")
        base_host = base_host.lstrip("www.")
        return url_host == base_host or url_host.endswith(f".{base_host}")
    except Exception:
        return False


def extract_base_url(url: str) -> str:
    """Extract scheme + host from a URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_static_resource(url: str, static_extensions: Set[str]) -> bool:
    """Check if URL points to a static resource."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in static_extensions)


def join_url(base: str, path: str) -> str:
    """Safely join a base URL with a relative path."""
    try:
        return urljoin(base, path)
    except Exception:
        return ""


def extract_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from a URL."""
    try:
        return parse_qs(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return {}


def inject_param(url: str, param: str, value: str) -> str:
    """Replace or inject a parameter value in a URL."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


def inject_all_params(url: str, value: str) -> List[Tuple[str, str]]:
    """Return list of (param_name, injected_url) for each parameter."""
    results = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            new_params = dict(params)
            new_params[param] = [value]
            new_query = urlencode(new_params, doseq=True)
            injected = urlunparse(parsed._replace(query=new_query))
            results.append((param, injected))
    except Exception:
        pass
    return results


def sanitize_filename(s: str) -> str:
    """Make a string safe for use as a filename."""
    s = re.sub(r"[^\w\-_\. ]", "_", s)
    return s[:100].strip()


def truncate(text: str, max_len: int = 80) -> str:
    """Truncate a string with ellipsis."""
    return text if len(text) <= max_len else text[:max_len - 3] + "..."


def elapsed_str(seconds: float) -> str:
    """Format elapsed seconds as a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def safe_get(d: dict, *keys, default=None):
    """Safely get a nested dict value."""
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key, default)
    return d


def chunk_list(lst: list, size: int) -> List[list]:
    """Split list into chunks of given size."""
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def deduplicate_findings(findings: list) -> list:
    """Remove duplicate vulnerability findings based on type + url + parameter."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type", ""), f.get("url", ""), f.get("parameter", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def confidence_label(score: int) -> str:
    """Convert confidence score to label."""
    if score >= 90:  return "Confirmed"
    if score >= 70:  return "Probable"
    if score >= 50:  return "Possible"
    return "Speculative"


def severity_color_code(severity: str) -> str:
    """Return ANSI color for severity."""
    mapping = {
        "critical": "\033[35m",  # magenta
        "high":     "\033[31m",  # red
        "medium":   "\033[33m",  # yellow
        "low":      "\033[32m",  # green
        "info":     "\033[36m",  # cyan
    }
    return mapping.get(severity.lower(), "\033[37m")


def rate_limiter(last_request_time: float, min_delay: float) -> float:
    """
    Sleep if needed to respect rate limit.
    Returns the current time after sleeping.
    """
    elapsed = time.time() - last_request_time
    if elapsed < min_delay:
        time.sleep(min_delay - elapsed)
    return time.time()
