import os
import sys


class TerminalStyle:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"

    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    CYAN = "\x1b[36m"

    def __init__(self, force_color: bool = False):
        self.enabled = self._supports_color(force_color)

    @staticmethod
    def _supports_color(force_color: bool) -> bool:
        if force_color:
            return True
        if os.getenv("NO_COLOR"):
            return False
        if os.getenv("TERM", "").lower() == "dumb":
            return False
        return sys.stdout.isatty()

    def paint(self, text: str, color: str = "", bold: bool = False, dim: bool = False) -> str:
        if not self.enabled:
            return text

        prefix = ""
        if bold:
            prefix += self.BOLD
        if dim:
            prefix += self.DIM
        if color:
            prefix += color
        return f"{prefix}{text}{self.RESET}"

    def banner(self, title: str) -> str:
        edge = "=" * max(18, len(title) + 6)
        line1 = self.paint(edge, self.CYAN, bold=True)
        line2 = self.paint(f"  {title}  ", self.BLUE, bold=True)
        return f"{line1}\n{line2}\n{line1}"

    def step(self, message: str) -> str:
        return self.paint(f"[+] {message}", self.GREEN, bold=True)

    def warn(self, message: str) -> str:
        return self.paint(f"[!] {message}", self.YELLOW, bold=True)

    def fail(self, message: str) -> str:
        return self.paint(f"[-] {message}", self.RED, bold=True)

    def info(self, message: str) -> str:
        return self.paint(f"[*] {message}", self.CYAN)
