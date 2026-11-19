"""Cross-platform helpers — sebelumnya `os.system('clear')` Linux-only."""
import os
import sys
import platform as _platform


def detect_env() -> str:
    """Deteksi environment: 'termux' | 'linux' | 'macos' | 'windows' | 'unknown'."""
    if "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    p = sys.platform
    if p.startswith("win"):  return "windows"
    if p == "darwin":        return "macos"
    if p.startswith("linux"): return "linux"
    return "unknown"


def clear_screen() -> None:
    if sys.platform.startswith("win"):
        os.system("cls")
    else:
        os.system("clear")


def safe_input(prompt: str = "") -> str:
    """Input wrapper yang handle EOF/KeyboardInterrupt → return '' bukan raise."""
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print()
        return ""


def banner_version() -> str:
    """Versi untuk banner."""
    return "v2.0.0-foundation"


def describe_env() -> str:
    """Ringkasan environment untuk banner."""
    try:
        py = _platform.python_version()
    except Exception:
        py = "?"
    return f"{detect_env()} | Python {py}"
