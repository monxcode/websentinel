"""
WebSentinel Framework - Authentication Handler
Handles form-based login, session capture, token extraction,
and authenticated session verification.
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, parse_qsl

import requests
from bs4 import BeautifulSoup

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


# ─────────────────────────────────────────────
# AUTH RESULT CONTAINER
# ─────────────────────────────────────────────


def _remove_cookie_by_name(jar, name: str) -> None:
    """
    Remove every cookie with the given name from a RequestsCookieJar,
    regardless of domain or path. Prevents CookieConflictError when
    the same cookie name appears under multiple domain/path combinations.
    """
    to_delete = []
    try:
        for domain, paths in jar._cookies.items():
            for path, cookies_dict in paths.items():
                if name in cookies_dict:
                    to_delete.append((domain, path, name))
        for domain, path, n in to_delete:
            del jar._cookies[domain][path][n]
    except Exception:
        pass


class AuthResult:
    """
    Holds the outcome of an authentication attempt.
    Carries cookies, tokens, and session state for use by the scan engine.
    """

    def __init__(
        self,
        success: bool,
        cookies: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        session_token: Optional[str] = None,
        csrf_token: Optional[str] = None,
        auth_method: str = "none",
        login_url: str = "",
        post_login_url: str = "",
        failure_reason: str = "",
        raw_cookies: List[str] = None,
    ):
        self.success = success
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.session_token = session_token
        self.csrf_token = csrf_token
        self.auth_method = auth_method
        self.login_url = login_url
        self.post_login_url = post_login_url
        self.failure_reason = failure_reason
        self.raw_cookies = raw_cookies or []

    def __bool__(self):
        return self.success

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "auth_method": self.auth_method,
            "login_url": self.login_url,
            "post_login_url": self.post_login_url,
            "session_cookies": list(self.cookies.keys()),
            "csrf_token_found": bool(self.csrf_token),
            "failure_reason": self.failure_reason,
        }

    def cookie_header(self) -> str:
        """Return cookies as a Cookie header string."""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


# ─────────────────────────────────────────────
# MAIN AUTH HANDLER CLASS
# ─────────────────────────────────────────────

class AuthHandler:
    """
    Manages authentication for WebSentinel scans.

    Supports:
    1. Form-based login   (--login "user=admin&pass=secret")
    2. Cookie injection   (--cookies "session=abc123")
    3. Token-only mode    (session cookie, no CSRF token required)
    4. Auto CSRF discovery (finds and includes CSRF tokens automatically)
    """

    # Common field name patterns for username and password
    USERNAME_FIELD_PATTERNS = [
        "username", "user", "email", "login", "user_name",
        "uname", "userid", "user_id", "account", "identifier",
        "name", "usr", "j_username", "log", "loginid"
    ]
    PASSWORD_FIELD_PATTERNS = [
        "password", "pass", "passwd", "pwd", "secret",
        "user_password", "passcode", "pin", "j_password",
        "userpassword", "new_password"
    ]
    CSRF_FIELD_PATTERNS = [
        "csrf_token", "csrftoken", "_token", "csrf", "token",
        "authenticity_token", "_csrf_token", "__requestverificationtoken",
        "xsrf_token", "antiforgery_token", "form_key",
    ]

    # Patterns indicating login failure in response body
    FAILURE_PATTERNS = [
        "invalid username", "invalid password", "incorrect password",
        "wrong password", "login failed", "authentication failed",
        "invalid credentials", "bad credentials", "access denied",
        "login error", "invalid login", "user not found",
        "account not found", "incorrect username",
        "غلط پاسورڈ", "invalid email", "invalid email or password",
    ]

    # Patterns indicating login success
    SUCCESS_PATTERNS = [
        "dashboard", "welcome", "logout", "sign out", "signout",
        "profile", "account", "my account", "settings",
        "logged in", "you are now logged in", "login successful",
    ]

    def __init__(
        self,
        session: requests.Session,
        timeout: int = config.DEFAULT_TIMEOUT,
        logger=None,
    ):
        self.session = session
        self.timeout = timeout
        self.logger = logger
        self._last_csrf = None

    # ─────────────────────────────────────────────
    # PUBLIC: LOGIN WITH CREDENTIALS
    # ─────────────────────────────────────────────

    def login(
        self,
        login_url: str,
        credentials: str,
        extra_cookies: Dict[str, str] = None,
    ) -> AuthResult:
        """
        Perform form-based authentication.

        :param login_url:    URL of the login page (GET to discover form, POST to submit)
        :param credentials:  Credential string, e.g. "username=admin&password=secret"
        :param extra_cookies: Pre-existing cookies to include in session
        :return: AuthResult with success status, cookies, and session info
        """
        self._log(f"Starting authentication → {login_url}")

        # Inject any pre-provided cookies before login
        if extra_cookies:
            self.session.cookies.update(extra_cookies)
            self._log(f"Pre-loaded {len(extra_cookies)} cookie(s): {list(extra_cookies.keys())}")

        # Parse credentials
        cred_dict = self._parse_credentials(credentials)
        if not cred_dict:
            return AuthResult(
                success=False,
                failure_reason="Could not parse credentials from --login string",
                auth_method="form",
                login_url=login_url,
            )

        # Step 1: GET login page → discover form + CSRF token
        login_page = self._fetch_login_page(login_url)
        if login_page is None:
            return AuthResult(
                success=False,
                failure_reason=f"Failed to load login page: {login_url}",
                auth_method="form",
                login_url=login_url,
            )

        # Step 2: Build POST payload
        post_data, form_action, method = self._build_post_payload(
            login_page, login_url, cred_dict
        )
        self._log(f"Form action: {form_action} ({method})")
        self._log(f"POST fields: {list(post_data.keys())}")

        # Step 3: Submit login form
        post_result = self._submit_login(form_action, post_data, method, login_url)
        if post_result is None:
            return AuthResult(
                success=False,
                failure_reason="Login POST request failed (network error)",
                auth_method="form",
                login_url=login_url,
            )

        # Step 4: Detect success / failure
        success, reason, post_login_url = self._detect_login_outcome(
            post_result, login_url, cred_dict
        )

        # Collect all cookies from session
        all_cookies = dict(self.session.cookies)
        session_token = self._extract_session_token(all_cookies)
        csrf_token = self._last_csrf

        if success:
            self._log_success(all_cookies, session_token, post_login_url)
            return AuthResult(
                success=True,
                cookies=all_cookies,
                session_token=session_token,
                csrf_token=csrf_token,
                auth_method="form",
                login_url=login_url,
                post_login_url=post_login_url,
                raw_cookies=self._get_raw_cookies(),
            )
        else:
            return AuthResult(
                success=False,
                cookies=all_cookies,  # partial cookies still passed through
                failure_reason=reason,
                auth_method="form",
                login_url=login_url,
                post_login_url=post_login_url,
            )

    # ─────────────────────────────────────────────
    # PUBLIC: COOKIE-ONLY SESSION
    # ─────────────────────────────────────────────

    def apply_cookies(
        self,
        cookies: Dict[str, str],
        target_url: str,
    ) -> AuthResult:
        """
        Apply pre-provided cookies to the session and verify they grant access.
        No login form interaction — pure cookie injection.

        :param cookies:     Dict of cookie name → value
        :param target_url:  URL to verify session against
        :return: AuthResult
        """
        self._log(f"Applying {len(cookies)} session cookie(s): {list(cookies.keys())}")
        # Clear duplicates before setting to avoid CookieConflictError.
        # session.cookies.clear(name=...) requires domain+path, so we
        # delete directly from the internal _cookies dict instead.
        for name, value in cookies.items():
            _remove_cookie_by_name(self.session.cookies, name)
            self.session.cookies.set(name, value)

        # Verify cookies work by requesting target
        try:
            resp = self.session.get(
                target_url, timeout=self.timeout,
                verify=False, allow_redirects=True
            )
            all_cookies = dict(self.session.cookies)
            session_token = self._extract_session_token(all_cookies)

            # Consider "success" if we got a non-error response
            success = resp.status_code < 400
            post_url = resp.url

            if success:
                self._log(f"Cookie session active — status {resp.status_code} @ {post_url}")
            else:
                self._log(f"Cookie session returned {resp.status_code} — may be invalid")

            return AuthResult(
                success=success,
                cookies=all_cookies,
                session_token=session_token,
                auth_method="cookie",
                login_url=target_url,
                post_login_url=post_url,
                failure_reason="" if success else f"HTTP {resp.status_code}",
                raw_cookies=self._get_raw_cookies(),
            )
        except Exception as e:
            return AuthResult(
                success=False,
                cookies=cookies,
                failure_reason=str(e)[:100],
                auth_method="cookie",
                login_url=target_url,
            )

    # ─────────────────────────────────────────────
    # PUBLIC: SESSION VERIFICATION
    # ─────────────────────────────────────────────

    def verify_session(self, url: str) -> Tuple[bool, str]:
        """
        Verify that the current session is still authenticated.
        Returns (is_authenticated, reason).
        """
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            body_lower = resp.text.lower()

            # Redirect back to login = session expired
            final_path = urlparse(resp.url).path.lower()
            login_paths = ["/login", "/signin", "/auth", "/account/login"]
            if any(lp in final_path for lp in login_paths):
                return False, f"Redirected to login page: {resp.url}"

            # Check for success indicators
            if any(p in body_lower for p in ["logout", "sign out", "dashboard", "welcome"]):
                return True, "Authenticated session confirmed"

            if resp.status_code == 200:
                return True, f"HTTP 200 received (session likely valid)"

            return False, f"HTTP {resp.status_code} — session may be expired"
        except Exception as e:
            return False, f"Verification error: {str(e)[:60]}"

    # ─────────────────────────────────────────────
    # INTERNAL: PAGE FETCH
    # ─────────────────────────────────────────────

    def _fetch_login_page(self, login_url: str) -> Optional[BeautifulSoup]:
        """GET the login page and return parsed BeautifulSoup."""
        try:
            resp = self.session.get(
                login_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            if resp.status_code >= 400:
                self._log(f"Login page returned HTTP {resp.status_code}")
                return None
            return BeautifulSoup(resp.text, "html.parser")
        except Exception as e:
            self._log(f"Failed to fetch login page: {e}")
            return None

    # ─────────────────────────────────────────────
    # INTERNAL: FORM DISCOVERY & PAYLOAD BUILD
    # ─────────────────────────────────────────────

    def _build_post_payload(
        self,
        soup: BeautifulSoup,
        login_url: str,
        cred_dict: Dict[str, str],
    ) -> Tuple[Dict, str, str]:
        """
        Discover login form on page, map credential fields,
        and inject CSRF tokens. Returns (post_data, action_url, method).
        """
        # Find all forms
        forms = soup.find_all("form")
        login_form = self._identify_login_form(forms)

        if login_form:
            action = login_form.get("action", "")
            method = login_form.get("method", "POST").upper()
            form_action = urljoin(login_url, action) if action else login_url

            # Start with all existing form hidden fields
            post_data = {}
            for inp in login_form.find_all(["input", "select", "textarea"]):
                name = inp.get("name", "")
                value = inp.get("value", "")
                ftype = inp.get("type", "text").lower()
                if name:
                    if ftype == "hidden":
                        post_data[name] = value
                        # Check if it's a CSRF token
                        if any(p in name.lower() for p in self.CSRF_FIELD_PATTERNS):
                            self._last_csrf = value
                            self._log(f"CSRF token found: {name} = {value[:20]}...")
                    elif ftype not in ("submit", "button", "image", "reset"):
                        post_data[name] = ""  # placeholder, will be replaced

            # Map credentials to form fields
            user_field, pass_field = self._detect_credential_fields(login_form)

            # Override with detected fields
            if user_field and "user" in cred_dict:
                post_data[user_field] = cred_dict["user"]
                self._log(f"Username field mapped: '{user_field}'")
            if pass_field and "pass" in cred_dict:
                post_data[pass_field] = cred_dict["pass"]
                self._log(f"Password field mapped: '{pass_field}'")

            # Also inject by exact key names from credential string
            for k, v in cred_dict.items():
                if k not in ("user", "pass"):
                    post_data[k] = v

        else:
            # No form found — construct payload from credentials directly
            self._log("No login form detected — using raw credential payload")
            form_action = login_url
            method = "POST"
            post_data = dict(cred_dict)

        return post_data, form_action, method

    def _identify_login_form(self, forms: list) -> Optional[any]:
        """Identify which form is the login form."""
        # Priority 1: form with password field
        for form in forms:
            inputs = form.find_all("input")
            types = [i.get("type", "text").lower() for i in inputs]
            if "password" in types:
                return form

        # Priority 2: form with login-related action
        for form in forms:
            action = form.get("action", "").lower()
            if any(kw in action for kw in ["login", "signin", "auth", "session"]):
                return form

        # Fallback: first form
        return forms[0] if forms else None

    def _detect_credential_fields(
        self, form
    ) -> Tuple[Optional[str], Optional[str]]:
        """Auto-detect username and password field names in a form."""
        user_field = None
        pass_field = None

        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            ftype = (inp.get("type") or "text").lower()
            placeholder = (inp.get("placeholder") or "").lower()
            combined = f"{name} {placeholder}"

            if ftype == "password" and not pass_field:
                pass_field = inp.get("name")
            elif ftype in ("text", "email") and not user_field:
                if any(p in combined for p in self.USERNAME_FIELD_PATTERNS):
                    user_field = inp.get("name")

        # If user field not found by pattern, take first text/email field
        if not user_field:
            for inp in form.find_all("input"):
                ftype = (inp.get("type") or "text").lower()
                if ftype in ("text", "email"):
                    user_field = inp.get("name")
                    break

        return user_field, pass_field

    # ─────────────────────────────────────────────
    # INTERNAL: FORM SUBMISSION
    # ─────────────────────────────────────────────

    def _submit_login(
        self,
        form_action: str,
        post_data: Dict,
        method: str,
        referer: str,
    ) -> Optional[requests.Response]:
        """Submit the login form."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": referer,
            "Origin": f"{urlparse(referer).scheme}://{urlparse(referer).netloc}",
        }
        try:
            if method == "POST":
                resp = self.session.post(
                    form_action,
                    data=post_data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
            else:
                resp = self.session.get(
                    form_action,
                    params=post_data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
            self._log(f"Login POST → {resp.status_code} | Final URL: {resp.url}")
            return resp
        except Exception as e:
            self._log(f"Login POST failed: {e}")
            return None

    # ─────────────────────────────────────────────
    # INTERNAL: SUCCESS / FAILURE DETECTION
    # ─────────────────────────────────────────────

    def _detect_login_outcome(
        self,
        resp: requests.Response,
        login_url: str,
        cred_dict: Dict,
    ) -> Tuple[bool, str, str]:
        """
        Determine if login succeeded.
        Returns (success, reason, post_login_url).
        """
        body_lower = resp.text.lower()
        final_url = resp.url
        final_path = urlparse(final_url).path.lower()
        login_path = urlparse(login_url).path.lower()

        # Strong failure: still on login page with error message
        failure_msgs = [p for p in self.FAILURE_PATTERNS if p in body_lower]
        if failure_msgs:
            return False, f"Login failure message detected: '{failure_msgs[0]}'", final_url

        # Strong success: redirected away from login page
        if final_path != login_path and not any(
            lp in final_path for lp in ["/login", "/signin", "/auth/login"]
        ):
            return True, "Redirected to authenticated area", final_url

        # Success signals in body
        if any(p in body_lower for p in self.SUCCESS_PATTERNS):
            return True, "Authenticated session indicators detected in response", final_url

        # New cookies were set — likely authenticated
        new_cookies = dict(self.session.cookies)
        if new_cookies and any(
            k.lower() in ("sessionid", "session", "phpsessid", "jsessionid",
                          "auth_token", "access_token", "remember_token")
            for k in new_cookies
        ):
            return True, "Session cookie received — login likely successful", final_url

        # HTTP 302 redirect is strong success signal
        if resp.history and resp.history[-1].status_code in (301, 302, 303):
            return True, "Login redirect received (302) — likely successful", final_url

        # 200 on a different path — ambiguous but pass through
        if resp.status_code == 200 and final_path != login_path:
            return True, f"HTTP 200 on non-login path: {final_path}", final_url

        return False, "Could not confirm login success — check credentials", final_url

    # ─────────────────────────────────────────────
    # INTERNAL: CREDENTIAL PARSING
    # ─────────────────────────────────────────────

    def _parse_credentials(self, cred_string: str) -> Dict[str, str]:
        """
        Parse credential string into a dict.

        Supports:
            "username=admin&password=secret"
            "user=admin&pass=secret"
            "email=admin@example.com&password=secret"
        """
        if not cred_string:
            return {}

        try:
            # URL-form decode
            pairs = parse_qsl(cred_string, keep_blank_values=True)
            raw = {k: v for k, v in pairs}
        except Exception:
            raw = {}

        if not raw:
            return {}

        # Normalize to internal keys "user" and "pass" for field detection
        normalized = dict(raw)
        for key, val in raw.items():
            key_lower = key.lower()
            if any(p in key_lower for p in self.USERNAME_FIELD_PATTERNS):
                normalized["user"] = val
            if any(p in key_lower for p in self.PASSWORD_FIELD_PATTERNS):
                normalized["pass"] = val

        self._log(f"Parsed credentials — fields: {list(raw.keys())}")
        return normalized

    # ─────────────────────────────────────────────
    # INTERNAL: TOKEN & COOKIE EXTRACTION
    # ─────────────────────────────────────────────

    @staticmethod
    def _extract_session_token(cookies: Dict[str, str]) -> Optional[str]:
        """
        Extract the most likely session token from cookies.
        Prefers: sessionid → session → phpsessid → jsessionid → access_token → first cookie.
        """
        priority = [
            "sessionid", "session", "phpsessid", "jsessionid",
            "access_token", "auth_token", "remember_token",
            "SESSIONID", "SESSION", "PHPSESSID"
        ]
        cookies_lower = {k.lower(): v for k, v in cookies.items()}
        for name in priority:
            if name.lower() in cookies_lower:
                return cookies_lower[name.lower()]
        # Fallback: return first cookie value
        return next(iter(cookies.values()), None) if cookies else None

    def _get_raw_cookies(self) -> List[str]:
        """Return raw cookie strings from the session."""
        raw = []
        for cookie in self.session.cookies:
            parts = [f"{cookie.name}={cookie.value}"]
            if cookie.domain:
                parts.append(f"Domain={cookie.domain}")
            if cookie.path:
                parts.append(f"Path={cookie.path}")
            if cookie.secure:
                parts.append("Secure")
            raw.append("; ".join(parts))
        return raw

    # ─────────────────────────────────────────────
    # INTERNAL: LOGGING HELPERS
    # ─────────────────────────────────────────────

    def _log(self, msg: str):
        if self.logger:
            self.logger.debug(f"[AuthHandler] {msg}")

    def _log_success(
        self,
        cookies: Dict,
        session_token: Optional[str],
        post_url: str,
    ):
        """Log minimal auth details — main.py logs the full summary to avoid duplicates."""
        if self.logger and session_token:
            masked = session_token[:8] + "..." + session_token[-4:] if len(session_token) > 12 else "***"
            self.logger.success(f"Session token    : {masked}")


# ─────────────────────────────────────────────
# UTILITY: Parse --cookies string
# ─────────────────────────────────────────────

def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """
    Parse a cookie string (semicolon-separated) into a dict.

    Accepts:
        "session=abc123"
        "session=abc; token=xyz; user_id=42"
        "PHPSESSID=abc123; security=low"
    """
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                cookies[k] = v
        else:
            # Flag-style cookie with no value
            if part:
                cookies[part] = ""
    return cookies
