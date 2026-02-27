"""
WebSentinel Framework - Request Engine
Handles all HTTP requests with throttling, retries, and session management.
"""

import time
import random
import requests
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


class RequestResult:
    """Container for a single HTTP request result."""

    def __init__(
        self,
        url: str,
        status_code: int = 0,
        headers: Dict = None,
        body: str = "",
        elapsed: float = 0.0,
        error: Optional[str] = None,
        redirected: bool = False,
        final_url: str = "",
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        self.elapsed = elapsed
        self.error = error
        self.redirected = redirected
        self.final_url = final_url or url
        self.content_length = len(body)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code > 0

    def __repr__(self):
        return f"<RequestResult [{self.status_code}] {self.url}>"


class RequestEngine:
    """
    Intelligent HTTP request engine with rate limiting, retries,
    session management, and configurable delays.
    """

    def __init__(
        self,
        delay: float = config.DEFAULT_DELAY,
        max_rps: float = config.MAX_REQUESTS_PER_SECOND,
        timeout: int = config.DEFAULT_TIMEOUT,
        retries: int = config.DEFAULT_RETRIES,
        cookies: Optional[Dict] = None,
        extra_headers: Optional[Dict] = None,
        random_delay: bool = True,
        delay_range: tuple = (0.5, 2.0),
    ):
        self.delay = delay
        self.max_rps = max_rps
        self.min_delay = 1.0 / max_rps if max_rps > 0 else 1.0
        self.timeout = timeout
        self.retries = retries
        self.random_delay = random_delay
        self.delay_range = delay_range
        self._last_request_time: float = 0.0
        self._request_count: int = 0

        # Build session
        self.session = requests.Session()
        self.session.headers.update(config.DEFAULT_HEADERS)
        if extra_headers:
            self.session.headers.update(extra_headers)
        if cookies:
            self.session.cookies.update(cookies)

        # Configure retry adapter
        retry = Retry(
            total=retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _throttle(self):
        """Enforce rate limiting with optional random jitter."""
        now = time.time()
        elapsed = now - self._last_request_time
        required_gap = self.min_delay

        if self.random_delay:
            jitter = random.uniform(*self.delay_range)
            required_gap = max(required_gap, jitter)

        if elapsed < required_gap:
            time.sleep(required_gap - elapsed)
        self._last_request_time = time.time()

    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        allow_redirects: bool = True,
        extra_headers: Optional[Dict] = None,
    ) -> RequestResult:
        """Perform a GET request with throttling and error handling."""
        self._throttle()
        self._request_count += 1
        headers = dict(self.session.headers)
        if extra_headers:
            headers.update(extra_headers)

        t0 = time.time()
        try:
            resp = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False,
            )
            elapsed = time.time() - t0
            try:
                body = resp.text
            except Exception:
                body = ""

            return RequestResult(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                elapsed=elapsed,
                redirected=(resp.url != url),
                final_url=resp.url,
            )
        except requests.exceptions.Timeout:
            return RequestResult(url=url, error="Timeout", elapsed=time.time() - t0)
        except requests.exceptions.ConnectionError as e:
            return RequestResult(url=url, error=f"ConnectionError: {str(e)[:80]}", elapsed=time.time() - t0)
        except requests.exceptions.TooManyRedirects:
            return RequestResult(url=url, error="TooManyRedirects", elapsed=time.time() - t0)
        except Exception as e:
            return RequestResult(url=url, error=str(e)[:100], elapsed=time.time() - t0)

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        extra_headers: Optional[Dict] = None,
    ) -> RequestResult:
        """Perform a POST request."""
        self._throttle()
        self._request_count += 1
        headers = dict(self.session.headers)
        if extra_headers:
            headers.update(extra_headers)

        t0 = time.time()
        try:
            resp = self.session.post(
                url,
                data=data,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
                verify=False,
            )
            elapsed = time.time() - t0
            try:
                body = resp.text
            except Exception:
                body = ""
            return RequestResult(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                elapsed=elapsed,
                redirected=(resp.url != url),
                final_url=resp.url,
            )
        except Exception as e:
            return RequestResult(url=url, error=str(e)[:100], elapsed=time.time() - t0)

    def head(self, url: str) -> RequestResult:
        """Perform a HEAD request (lightweight)."""
        self._throttle()
        self._request_count += 1
        t0 = time.time()
        try:
            resp = self.session.head(url, timeout=self.timeout, verify=False)
            return RequestResult(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                elapsed=time.time() - t0,
            )
        except Exception as e:
            return RequestResult(url=url, error=str(e)[:100], elapsed=time.time() - t0)

    @property
    def request_count(self) -> int:
        return self._request_count

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
