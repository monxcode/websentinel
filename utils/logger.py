"""
WebSentinel Framework - Logger Utility
Colored terminal logging with stage indicators and progress tracking.
"""

import sys
import time
from datetime import datetime
from colorama import Fore, Back, Style, init

init(autoreset=True)

ASCII_BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
 ██╗    ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ╚███╔███╔╝███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{Style.RESET_ALL}"""

SUBTITLE = (
    f"  {Fore.WHITE}{Style.BRIGHT}⚡  Advanced Web Application Security Assessment Framework  v1.0.0{Style.RESET_ALL}\n"
    f"  {Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}\n"
)

LEVEL_CONFIG = {
    "info":     (Fore.CYAN,    "ℹ",  "INFO    "),
    "success":  (Fore.GREEN,   "✔",  "SUCCESS "),
    "warning":  (Fore.YELLOW,  "⚠",  "WARNING "),
    "error":    (Fore.RED,     "✘",  "ERROR   "),
    "critical": (Fore.MAGENTA, "☠",  "CRITICAL"),
    "scan":     (Fore.BLUE,    "⊛",  "SCAN    "),
    "vuln":     (Fore.RED,     "🔥", "VULN    "),
    "safe":     (Fore.GREEN,   "🛡",  "SAFE    "),
    "debug":    (Fore.WHITE,   "·",  "DEBUG   "),
    "stage":    (Fore.CYAN,    "►",  "STAGE   "),
}


class Logger:
    """Terminal logger with color support and scan stage tracking."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._stage_count = 0
        self._start_time = time.time()

    def _timestamp(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def log(self, level: str, message: str):
        color, icon, label = LEVEL_CONFIG.get(level, (Fore.WHITE, "·", "LOG     "))
        ts = f"{Fore.WHITE}{Style.DIM}[{self._timestamp()}]{Style.RESET_ALL}"
        lbl = f"{color}{Style.BRIGHT}[{label.strip()}]{Style.RESET_ALL}"
        ico = f"{color}{icon}{Style.RESET_ALL}"
        print(f"  {ts} {lbl} {ico}  {message}")

    def info(self, msg: str):      self.log("info", msg)
    def success(self, msg: str):   self.log("success", msg)
    def warning(self, msg: str):   self.log("warning", msg)
    def error(self, msg: str):     self.log("error", msg)
    def critical(self, msg: str):  self.log("critical", msg)
    def scan(self, msg: str):      self.log("scan", msg)
    def vuln(self, msg: str):      self.log("vuln", msg)
    def safe(self, msg: str):      self.log("safe", msg)
    def debug(self, msg: str):
        if self.verbose:
            self.log("debug", msg)

    def stage(self, title: str):
        self._stage_count += 1
        elapsed = time.time() - self._start_time
        bar = f"{Fore.CYAN}{'━' * 60}{Style.RESET_ALL}"
        print(f"\n  {bar}")
        print(
            f"  {Fore.CYAN}{Style.BRIGHT}  STAGE {self._stage_count:02d}  ►  {title.upper()}"
            f"{Style.RESET_ALL}  {Fore.WHITE}{Style.DIM}(+{elapsed:.1f}s){Style.RESET_ALL}"
        )
        print(f"  {bar}\n")

    def progress(self, current: int, total: int, label: str = ""):
        """Inline progress bar."""
        pct = int((current / max(total, 1)) * 40)
        bar = f"{'█' * pct}{'░' * (40 - pct)}"
        sys.stdout.write(
            f"\r  {Fore.CYAN}[{bar}]{Style.RESET_ALL} "
            f"{Fore.WHITE}{current}/{total}{Style.RESET_ALL}  {label[:50]:<50}"
        )
        sys.stdout.flush()
        if current >= total:
            print()

    def banner(self):
        print(ASCII_BANNER)
        print(SUBTITLE)

    def summary_box(self, title: str, lines: list):
        """Print a formatted summary box."""
        width = 68
        top    = f"  {Fore.CYAN}╔{'═' * width}╗{Style.RESET_ALL}"
        bottom = f"  {Fore.CYAN}╚{'═' * width}╝{Style.RESET_ALL}"
        mid    = f"  {Fore.CYAN}╠{'═' * width}╣{Style.RESET_ALL}"
        header = f"  {Fore.CYAN}║{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}{title.center(width - 2)}{Style.RESET_ALL}  {Fore.CYAN}║{Style.RESET_ALL}"
        print(f"\n{top}")
        print(header)
        print(mid)
        for line in lines:
            content = line[:width - 2]
            padding = " " * (width - 2 - len(content))
            print(f"  {Fore.CYAN}║{Style.RESET_ALL}  {content}{padding}  {Fore.CYAN}║{Style.RESET_ALL}")
        print(bottom)
        print()

    def separator(self, char: str = "─", width: int = 72):
        print(f"  {Fore.WHITE}{Style.DIM}{char * width}{Style.RESET_ALL}")
