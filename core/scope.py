import sys
import fnmatch
from urllib.parse import urlparse

class ScopeManager:
    def __init__(self):
        self.authorized_patterns = ["localhost", "127.0.0.1", "*.local", "*.test", "*.lab", "*.ctf"]
        self.interactive_confirmed = set()

    def is_in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host: return False
        if any(fnmatch.fnmatch(host, p) for p in self.authorized_patterns): return True
        if host in self.interactive_confirmed: return True
        return False

    def confirm_scope(self, url: str) -> bool:
        if self.is_in_scope(url): return True
        host = (urlparse(url).hostname or "").lower()
        
        if not sys.stdin.isatty():
            print(f"\n[!] Target ({host}) is outside scope, non-interactive. Denied.")
            return False
            
        print(f"\n[!] Target ({host}) is outside the whitelist.")
        ans = input("    Type 'AUTHORIZED' if you have permission to test: ").strip()
        if ans == "AUTHORIZED":
            self.interactive_confirmed.add(host)
            if host.startswith("www."): self.interactive_confirmed.add(host[4:])
            else: self.interactive_confirmed.add(f"www.{host}")
            return True
        return False
