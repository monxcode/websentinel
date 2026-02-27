"""
WebSentinel Framework - Crawler Engine
Advanced web crawler with link discovery, form detection, and endpoint classification.
"""

import re
import xml.etree.ElementTree as ET
from collections import deque
from typing import Set, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

from bs4 import BeautifulSoup

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from utils.helpers import (
    normalize_url, url_fingerprint, is_same_domain,
    is_static_resource, join_url, extract_params, extract_base_url
)


class Endpoint:
    """Represents a discovered web endpoint."""

    def __init__(
        self,
        url: str,
        method: str = "GET",
        params: Dict = None,
        forms: List = None,
        endpoint_type: str = "unknown",
        depth: int = 0,
        source_url: str = "",
    ):
        self.url = url
        self.method = method
        self.params = params or {}
        self.forms = forms or []
        self.endpoint_type = endpoint_type
        self.depth = depth
        self.source_url = source_url
        self.fingerprint = url_fingerprint(url)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": list(self.params.keys()),
            "form_count": len(self.forms),
            "type": self.endpoint_type,
            "depth": self.depth,
        }


class CrawlerEngine:
    """
    Advanced crawler that discovers endpoints via BFS, parses sitemaps,
    robots.txt, and classifies each endpoint.
    """

    def __init__(
        self,
        base_url: str,
        engine,                     # RequestEngine instance
        max_depth: int = config.DEFAULT_CRAWL_DEPTH,
        respect_robots: bool = False,
        max_endpoints: int = config.MAX_ENDPOINTS_PER_SCAN,
        logger=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = extract_base_url(base_url)
        self.engine = engine
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.max_endpoints = max_endpoints
        self.logger = logger

        self.endpoints: Dict[str, Endpoint] = {}     # fingerprint -> Endpoint
        self.visited_urls: Set[str] = set()
        self.disallowed_paths: Set[str] = set()
        self.queue: deque = deque()

        self._link_re = re.compile(r'href=["\']([^"\'#]*)["\']', re.IGNORECASE)
        self._src_re  = re.compile(r'src=["\']([^"\'#]*)["\']', re.IGNORECASE)
        self._action_re = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)

    # ─────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────

    def crawl(self) -> List[Endpoint]:
        """Entry point: crawl from base URL."""
        if self.logger:
            self.logger.info(f"Starting crawl: {self.base_url}  depth={self.max_depth}")

        # Step 1: Parse robots.txt
        self._parse_robots()

        # Step 2: Parse sitemap
        self._parse_sitemap()

        # Step 3: BFS crawl from base
        self.queue.append((self.base_url, 0))
        while self.queue and len(self.endpoints) < self.max_endpoints:
            url, depth = self.queue.popleft()
            if depth > self.max_depth:
                continue
            norm = normalize_url(url)
            if norm in self.visited_urls:
                continue
            if self.respect_robots and self._is_disallowed(url):
                if self.logger:
                    self.logger.debug(f"Skipping disallowed: {url}")
                continue
            self.visited_urls.add(norm)
            self._crawl_page(url, depth)

        if self.logger:
            self.logger.success(
                f"Crawl complete — {len(self.endpoints)} unique endpoints discovered"
            )
        return list(self.endpoints.values())

    # ─────────────────────────────────────────────
    # INTERNAL METHODS
    # ─────────────────────────────────────────────

    def _crawl_page(self, url: str, depth: int):
        """Fetch and parse a single page."""
        result = self.engine.get(url, allow_redirects=True)
        if not result.ok:
            return

        soup = BeautifulSoup(result.body, "html.parser")
        params = extract_params(url)
        forms  = self._extract_forms(soup, url)
        ep_type = self._classify_endpoint(url, result)

        ep = Endpoint(
            url=result.final_url,
            params=params,
            forms=forms,
            endpoint_type=ep_type,
            depth=depth,
            source_url=url,
        )
        fp = url_fingerprint(url)
        if fp not in self.endpoints:
            self.endpoints[fp] = ep
            if self.logger:
                self.logger.debug(f"[{ep_type:8s}] {url}")

        # Discover child links
        if depth < self.max_depth:
            for link in self._extract_links(soup, url):
                norm = normalize_url(link)
                if norm not in self.visited_urls:
                    self.queue.append((link, depth + 1))

    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Extract all internal links from a page."""
        links = []
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag.get("href", "").strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                continue
            full_url = join_url(current_url, href)
            if not full_url:
                continue
            if not is_same_domain(full_url, self.base_url):
                continue
            if is_static_resource(full_url, config.STATIC_EXTENSIONS):
                continue
            links.append(full_url)

        # Also check src attributes for API-like endpoints
        for tag in soup.find_all(True, src=True):
            src = tag.get("src", "").strip()
            full = join_url(current_url, src)
            if full and is_same_domain(full, self.base_url):
                if not is_static_resource(full, config.STATIC_EXTENSIONS):
                    links.append(full)

        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Dict]:
        """Extract form definitions from a page."""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = join_url(page_url, action) if action else page_url

            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                ftype = inp.get("type", "text")
                if name:
                    fields.append({"name": name, "type": ftype})

            forms.append({
                "action": action_url,
                "method": method,
                "fields": fields,
            })

            # Register form action as endpoint too
            if action_url and is_same_domain(action_url, self.base_url):
                fp = url_fingerprint(action_url)
                if fp not in self.endpoints:
                    self.endpoints[fp] = Endpoint(
                        url=action_url,
                        method=method,
                        forms=[{"action": action_url, "method": method, "fields": fields}],
                        endpoint_type=self._classify_url(action_url),
                        source_url=page_url,
                    )
        return forms

    def _parse_robots(self):
        """Parse robots.txt to discover disallowed and additional paths."""
        robots_url = f"{self.base_domain}/robots.txt"
        result = self.engine.get(robots_url)
        if not result.ok or result.status_code != 200:
            return

        for line in result.body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    self.disallowed_paths.add(path)
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                self._parse_sitemap(sitemap_url)
            elif line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    full_url = f"{self.base_domain}{path}"
                    self.queue.append((full_url, 1))

        if self.logger:
            self.logger.info(f"robots.txt: {len(self.disallowed_paths)} disallowed paths")

    def _parse_sitemap(self, sitemap_url: str = None):
        """Parse sitemap.xml to discover URLs."""
        if sitemap_url is None:
            sitemap_url = f"{self.base_domain}/sitemap.xml"

        result = self.engine.get(sitemap_url)
        if not result.ok or result.status_code != 200:
            return

        try:
            root = ET.fromstring(result.body)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            count = 0
            # Regular sitemap
            for loc in root.findall(".//sm:loc", ns):
                url = loc.text.strip() if loc.text else ""
                if url and is_same_domain(url, self.base_url):
                    norm = normalize_url(url)
                    if norm not in self.visited_urls:
                        self.queue.append((url, 1))
                        count += 1
            # Sitemap index
            for sitemap in root.findall(".//sm:sitemap/sm:loc", ns):
                child_url = sitemap.text.strip() if sitemap.text else ""
                if child_url:
                    self._parse_sitemap(child_url)
            if self.logger and count:
                self.logger.info(f"Sitemap: {count} URLs discovered")
        except ET.ParseError:
            pass

    def _is_disallowed(self, url: str) -> bool:
        """Check if a URL path is disallowed by robots.txt."""
        path = urlparse(url).path
        return any(path.startswith(d) for d in self.disallowed_paths)

    def _classify_endpoint(self, url: str, result=None) -> str:
        """Classify an endpoint by URL pattern and response characteristics."""
        ep_type = self._classify_url(url)

        if result and ep_type == "dynamic":
            content_type = result.headers.get("Content-Type", "")
            if "application/json" in content_type:
                ep_type = "api"
            elif "text/xml" in content_type or "application/xml" in content_type:
                ep_type = "api"

        return ep_type

    def _classify_url(self, url: str) -> str:
        """Classify URL based on path patterns."""
        path = urlparse(url).path.lower()

        for pattern in config.ADMIN_PATH_PATTERNS:
            if pattern in path:
                return "admin"
        for pattern in config.AUTH_PATH_PATTERNS:
            if pattern in path:
                return "auth"
        for pattern in config.API_PATH_PATTERNS:
            if pattern in path:
                return "api"
        if is_static_resource(url, config.STATIC_EXTENSIONS):
            return "static"
        if "?" in url or any(c in path for c in ["{", "}", "[", "]"]):
            return "dynamic"
        return "dynamic" if path.count("/") > 1 else "static"

    def get_stats(self) -> Dict:
        """Return crawler statistics."""
        type_counts = {}
        for ep in self.endpoints.values():
            type_counts[ep.endpoint_type] = type_counts.get(ep.endpoint_type, 0) + 1
        return {
            "total_endpoints": len(self.endpoints),
            "visited_urls": len(self.visited_urls),
            "endpoint_types": type_counts,
            "endpoints_with_params": sum(1 for e in self.endpoints.values() if e.params),
            "endpoints_with_forms": sum(1 for e in self.endpoints.values() if e.forms),
        }
