import fnmatch
import json
import os
from urllib.parse import urlparse

def get_operator() -> str:
    env = os.environ.get("TANPHA_OPERATOR")
    if env: return env
    try:
        name = input("[?] Operator name (for audit log, default 'anonymous'): ").strip()
        return name or "anonymous"
    except (KeyboardInterrupt, EOFError):
        return "anonymous"

class ScopeManager:
    def __init__(self, scope_file: str = "scope.json"):
        self.scope_file = scope_file
        self.data = self._load_or_none()
        self.interactive_confirmed: set = set()

    def _load_or_none(self):
        if not os.path.exists(self.scope_file): return None
        try:
            with open(self.scope_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict): return None
            return data
        except Exception:
            return None

    def _match_host(self, host: str) -> bool:
        host = (host or "").lower()
        if not host: return False
        if self.data is None:
            local_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
            if host in local_hosts: return True
            if any(host.endswith(s) for s in (".local", ".test", ".lab", ".ctf", ".internal")): return True
            return False
        for pattern in self.data.get("authorized_hosts", []):
            if fnmatch.fnmatch(host, pattern.lower()): return True
        return False

    def confirm_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if self._match_host(host): return True
        if host in self.interactive_confirmed: return True

        print(f"[!] Target is not in scope ({host}).")
        print("[!] Use ONLY on systems you own or have written permission to test.")
        try:
            ans = input("    Type 'AUTHORIZED' to proceed: ").strip()
        except (KeyboardInterrupt, EOFError):
            return False

        if ans == "AUTHORIZED":
            self.interactive_confirmed.add(host)
            return True
        return False

    def summary(self) -> str:
        if self.data is None:
            return "scope.json not found — INTERACTIVE mode."
        op = self.data.get("operator", "?")
        eng = self.data.get("engagement", "?")
        hosts = ", ".join(self.data.get("authorized_hosts", []))
        return f"scope: operator={op}, engagement={eng}, hosts=[{hosts}]"
