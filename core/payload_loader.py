"""
WebSentinel Framework — Payload Loader
=======================================
Loads custom payloads from external files and merges them into the
active config at runtime. All vulnerability modules automatically
pick up the expanded payload lists — no module changes required.

Supported file formats
----------------------
  .txt    One payload per line. Lines starting with # are comments.
          Category is inferred from the filename or a section header.

  .json   Object with category keys mapping to string arrays.
          {
            "sqli":          ["' OR 1=1--", "admin'--"],
            "xss":           ["<script>alert(1)</script>"],
            "cmd":           [";id", "|whoami"],
            "lfi":           ["../../../../etc/passwd"],
            "ssrf":          ["http://169.254.169.254"],
            "nosql":         ["{\"$gt\":\"\"}"],
            "open_redirect": ["//evil.com"],
            "custom":        ["any_generic_payload"]
          }

  .csv    Two-column format: category,payload
          sqli,' OR 1=1--
          xss,<script>alert(1)</script>
          cmd,;id

Supported category names (case-insensitive)
-------------------------------------------
  sqli / sql / sqlinject / sql_injection
  xss / cross_site_scripting
  cmd / command / cmdinject / command_injection
  lfi / local_file_include / local_file_inclusion
  ssrf / server_side_request_forgery
  nosql / nosqli
  open_redirect / redirect
  custom  →  merged into all active categories
"""

import csv
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────
# CATEGORY ALIASES
# ─────────────────────────────────────────────

CATEGORY_MAP: Dict[str, str] = {
    # SQL Injection
    "sqli": "sqli",
    "sql": "sqli",
    "sql_injection": "sqli",
    "sqlinject": "sqli",
    "sqlinjection": "sqli",
    # XSS
    "xss": "xss",
    "cross_site_scripting": "xss",
    "crosssitescripting": "xss",
    # Command Injection
    "cmd": "cmd",
    "command": "cmd",
    "cmdinject": "cmd",
    "command_injection": "cmd",
    "commandinjection": "cmd",
    "rce": "cmd",
    # LFI
    "lfi": "lfi",
    "local_file_include": "lfi",
    "local_file_inclusion": "lfi",
    "localfileinclusion": "lfi",
    "path_traversal": "lfi",
    "traversal": "lfi",
    # SSRF
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "serversiderequestforgery": "ssrf",
    # NoSQL
    "nosql": "nosql",
    "nosqli": "nosql",
    "nosql_injection": "nosql",
    "nosqlinjection": "nosql",
    "mongodb": "nosql",
    # Open Redirect
    "open_redirect": "open_redirect",
    "redirect": "open_redirect",
    "openredirect": "open_redirect",
    # Generic — injected into all categories
    "custom": "custom",
    "generic": "custom",
    "all": "custom",
}

# Canonical category → config attribute name
CONFIG_ATTR: Dict[str, str] = {
    "sqli": "SQLI_PAYLOADS",
    "xss": "XSS_PAYLOADS",
    "cmd": "CMD_INJECTION_PAYLOADS",
    "lfi": "LFI_PAYLOADS",
    "ssrf": "SSRF_PAYLOADS",
    "nosql": "NOSQL_PAYLOADS",
    "open_redirect": "OPEN_REDIRECT_PAYLOADS",
}

# All canonical categories (excluding "custom")
ALL_CATEGORIES = list(CONFIG_ATTR.keys())


# ─────────────────────────────────────────────
# RESULT CONTAINER
# ─────────────────────────────────────────────


class PayloadLoadResult:
    """
    Holds the outcome of a payload file load operation.
    Carries per-category payload lists, counts, and any warnings.
    """

    def __init__(self):
        self.payloads: Dict[str, List[str]] = {cat: [] for cat in ALL_CATEGORIES}
        self.raw_custom: List[str] = []  # "custom" category payloads
        self.total_loaded: int = 0
        self.total_injected: int = 0
        self.skipped_blank: int = 0
        self.skipped_duplicate: int = 0
        self.warnings: List[str] = []
        self.source_file: str = ""
        self.file_format: str = ""

    def add(self, category: str, payload: str) -> bool:
        """
        Add a payload to its category list.
        Returns True if added, False if skipped (blank or duplicate).
        """
        payload = payload.strip()
        if not payload:
            self.skipped_blank += 1
            return False
        if category == "custom":
            if payload not in self.raw_custom:
                self.raw_custom.append(payload)
                self.total_loaded += 1
                return True
            self.skipped_duplicate += 1
            return False
        if category in self.payloads:
            if payload not in self.payloads[category]:
                self.payloads[category].append(payload)
                self.total_loaded += 1
                return True
            self.skipped_duplicate += 1
        return False

    def warn(self, msg: str):
        self.warnings.append(msg)

    def summary(self) -> str:
        parts = []
        for cat, lst in self.payloads.items():
            if lst:
                parts.append(f"{cat}={len(lst)}")
        if self.raw_custom:
            parts.append(f"custom={len(self.raw_custom)}")
        cat_str = ", ".join(parts) if parts else "none"
        return (
            f"Loaded {self.total_loaded} payload(s) from '{self.source_file}' "
            f"[{self.file_format}] — categories: {cat_str}"
        )


# ─────────────────────────────────────────────
# PAYLOAD LOADER CLASS
# ─────────────────────────────────────────────


class PayloadLoader:
    """
    Reads custom payload files, validates content, and merges
    the payloads into the active config module at runtime.

    Usage
    -----
        loader = PayloadLoader(config_module)
        result = loader.load("payloads/sqli.txt")
        loader.inject(result)
        # config.SQLI_PAYLOADS now includes custom payloads
    """

    # Maximum payloads per category to prevent runaway scans
    MAX_PER_CATEGORY = 500
    # Maximum file size (5 MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024

    def __init__(self, config_module, logger=None):
        self._cfg = config_module
        self._logger = logger

    # ─────────────────────────────────────────
    # PUBLIC: LOAD
    # ─────────────────────────────────────────

    def load(self, filepath: str) -> PayloadLoadResult:
        """
        Load payloads from an external file.

        Detects format from file extension (.txt / .json / .csv).
        Falls back to content-sniffing if extension is absent or unknown.

        :param filepath: Absolute or relative path to the payload file.
        :raises FileNotFoundError: If the file does not exist.
        :raises ValueError: If the file is empty, too large, or unparseable.
        :returns: PayloadLoadResult with loaded payload lists.
        """
        path = Path(filepath).expanduser().resolve()
        self._validate_file(path)

        result = PayloadLoadResult()
        result.source_file = str(path)

        ext = path.suffix.lower()
        if ext == ".json":
            self._load_json(path, result)
        elif ext == ".csv":
            self._load_csv(path, result)
        elif ext in (".txt", ".text", ".list", ""):
            self._load_txt(path, result)
        else:
            # Sniff content to determine format
            content = path.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("{") or content.startswith("["):
                self._load_json(path, result)
            elif "," in content.split("\n")[0]:
                self._load_csv(path, result)
            else:
                self._load_txt(path, result)

        return result

    # ─────────────────────────────────────────
    # PUBLIC: INJECT
    # ─────────────────────────────────────────

    def inject(self, result: PayloadLoadResult, prepend: bool = True) -> int:
        """
        Merge a PayloadLoadResult into the live config module.

        Custom payloads are inserted BEFORE the built-in payloads
        (prepend=True, default) so they are tested first. Pass
        prepend=False to append them after the built-in payloads.

        :param result:  A PayloadLoadResult from load().
        :param prepend: If True, custom payloads go first in the list.
        :returns: Total number of unique payloads injected.
        """
        injected = 0

        for category, new_payloads in result.payloads.items():
            if not new_payloads:
                continue
            attr = CONFIG_ATTR.get(category)
            if not attr or not hasattr(self._cfg, attr):
                result.warn(
                    f"Config attribute '{attr}' not found — skipping {category}"
                )
                continue

            existing: List[str] = getattr(self._cfg, attr)
            # Deduplicate against existing
            unique_new = [p for p in new_payloads if p not in existing]
            if not unique_new:
                continue

            # Enforce cap
            available = self.MAX_PER_CATEGORY - len(existing)
            if available <= 0:
                result.warn(
                    f"Category '{category}' is at the {self.MAX_PER_CATEGORY}-payload cap "
                    f"— {len(unique_new)} payload(s) not injected"
                )
                continue
            unique_new = unique_new[:available]

            if prepend:
                setattr(self._cfg, attr, unique_new + existing)
            else:
                setattr(self._cfg, attr, existing + unique_new)

            injected += len(unique_new)
            self._log(
                f"  {category:<14} +{len(unique_new)} payload(s) "
                f"→ {attr} now has {len(getattr(self._cfg, attr))} total"
            )

        # "custom" payloads go into ALL categories
        if result.raw_custom:
            added_to = 0
            for category, attr in CONFIG_ATTR.items():
                if not hasattr(self._cfg, attr):
                    continue
                existing = getattr(self._cfg, attr)
                unique_new = [p for p in result.raw_custom if p not in existing]
                if not unique_new:
                    continue
                available = self.MAX_PER_CATEGORY - len(existing)
                unique_new = unique_new[:available]
                if unique_new:
                    if prepend:
                        setattr(self._cfg, attr, unique_new + existing)
                    else:
                        setattr(self._cfg, attr, existing + unique_new)
                    injected += len(unique_new)
                    added_to += 1
            self._log(
                f"  {'custom':<14} {len(result.raw_custom)} payload(s) "
                f"→ injected into {added_to} categories"
            )

        result.total_injected = injected
        return injected

    # ─────────────────────────────────────────
    # PUBLIC: LOAD + INJECT IN ONE CALL
    # ─────────────────────────────────────────

    def load_and_inject(
        self,
        filepath: str,
        prepend: bool = True,
    ) -> PayloadLoadResult:
        """Convenience method: load a file and immediately inject into config."""
        result = self.load(filepath)
        self.inject(result, prepend=prepend)
        return result

    # ─────────────────────────────────────────
    # INTERNAL: FORMAT PARSERS
    # ─────────────────────────────────────────

    def _load_txt(self, path: Path, result: PayloadLoadResult):
        """
        Parse a plain-text payload file.

        Supports two modes:
          1. Flat list — every non-comment, non-blank line is a payload.
             Category is inferred from the filename stem.
          2. Sectioned — category headers in [brackets] switch the active category.
             [sqli]
             ' OR 1=1--
             [xss]
             <script>alert(1)</script>
        """
        result.file_format = "txt"
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        # Infer default category from filename
        stem = path.stem.lower().replace("-", "_")
        default_category = self._resolve_category(stem) or "custom"
        active_category = default_category

        for lineno, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # Skip comments and blank lines
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # Section header: [category_name]
            header_match = re.match(r"^\[([^\]]+)\]$", line)
            if header_match:
                label = header_match.group(1).strip().lower()
                resolved = self._resolve_category(label)
                if resolved:
                    active_category = resolved
                else:
                    result.warn(
                        f"Line {lineno}: Unknown category header '[{label}]' — "
                        f"remaining payloads will use '{active_category}'"
                    )
                continue

            result.add(active_category, line)

    def _load_json(self, path: Path, result: PayloadLoadResult):
        """
        Parse a JSON payload file.

        Expects an object with category keys:
          { "sqli": ["payload1", "payload2"], "xss": [...] }

        Also accepts a flat array — treated as "custom" category:
          ["payload1", "payload2"]
        """
        result.file_format = "json"
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in '{path.name}': {e}") from e

        if isinstance(data, list):
            # Flat array — treat as custom
            for item in data:
                if isinstance(item, str):
                    result.add("custom", item)
                else:
                    result.warn(f"Non-string item in JSON array skipped: {item!r}")
            return

        if not isinstance(data, dict):
            raise ValueError(
                f"JSON payload file must be an object (dict) or array. "
                f"Got: {type(data).__name__}"
            )

        for key, payloads in data.items():
            category = self._resolve_category(key.lower().strip())
            if not category:
                result.warn(f"Unknown category key '{key}' in JSON — skipped")
                continue
            if not isinstance(payloads, list):
                result.warn(f"Value for '{key}' must be a list — skipped")
                continue
            for item in payloads:
                if isinstance(item, str):
                    result.add(category, item)
                else:
                    result.warn(f"Non-string payload under '{key}' skipped: {item!r}")

    def _load_csv(self, path: Path, result: PayloadLoadResult):
        """
        Parse a CSV payload file.

        Expected columns: category, payload
          sqli,' OR 1=1--
          xss,<script>alert(1)</script>

        Header row is auto-detected and skipped.
        Single-column CSV is treated as a flat payload list (category="custom").
        """
        result.file_format = "csv"
        text = path.read_text(encoding="utf-8", errors="replace")
        reader = csv.reader(text.splitlines())

        stem = path.stem.lower().replace("-", "_")
        default_category = self._resolve_category(stem) or "custom"
        header_skipped = False

        for lineno, row in enumerate(reader, 1):
            if not row:
                continue

            # Skip header row
            if not header_skipped and row[0].lower().strip() in (
                "category",
                "type",
                "cat",
                "name",
                "module",
            ):
                header_skipped = True
                continue

            if len(row) == 1:
                # Single column — use default or custom
                result.add(default_category, row[0])

            elif len(row) >= 2:
                cat_raw = row[0].strip().lower()
                payload = ",".join(row[1:]).strip()  # re-join if payload had commas
                category = self._resolve_category(cat_raw)
                if not category:
                    result.warn(
                        f"Line {lineno}: Unknown category '{cat_raw}' — "
                        f"payload assigned to 'custom'"
                    )
                    category = "custom"
                result.add(category, payload)

    # ─────────────────────────────────────────
    # INTERNAL: VALIDATION & HELPERS
    # ─────────────────────────────────────────

    def _validate_file(self, path: Path):
        """Raise descriptive errors for invalid file paths or sizes."""
        if not path.exists():
            raise FileNotFoundError(
                f"Payload file not found: '{path}'\n"
                f"Tip: Use an absolute path or a path relative to the working directory."
            )
        if not path.is_file():
            raise ValueError(f"Path is not a file: '{path}'")
        size = path.stat().st_size
        if size == 0:
            raise ValueError(f"Payload file is empty: '{path}'")
        if size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"Payload file exceeds 5 MB limit ({size:,} bytes): '{path}'\n"
                f"Split the file into smaller category-specific files."
            )

    @staticmethod
    def _resolve_category(raw: str) -> Optional[str]:
        """Resolve a raw string to a canonical category name. Returns None if unknown."""
        return CATEGORY_MAP.get(raw.strip().lower().replace("-", "_").replace(" ", "_"))

    def _log(self, msg: str):
        if self._logger:
            self._logger.info(msg)
        else:
            print(msg)


# ─────────────────────────────────────────────
# STANDALONE HELPER: validate file path early
# ─────────────────────────────────────────────


def validate_payload_file(filepath: str) -> Tuple[bool, str]:
    """
    Quick pre-flight check for a payload file path.
    Returns (ok: bool, message: str).
    Call this during argument parsing before engines are initialized.
    """
    path = Path(filepath).expanduser().resolve()
    if not path.exists():
        return False, f"Payload file not found: '{path}'"
    if not path.is_file():
        return False, f"Not a file: '{path}'"
    if path.stat().st_size == 0:
        return False, f"Payload file is empty: '{path}'"
    ext = path.suffix.lower()
    if ext not in (".txt", ".json", ".csv", ".text", ".list", ""):
        return False, (
            f"Unsupported file extension '{ext}'. " f"Supported: .txt, .json, .csv"
        )
    return True, f"Payload file OK: '{path.name}' ({path.stat().st_size:,} bytes)"
