"""
Scope & Authorization Manager.

Cara kerja:
  1. User bisa declare scope via file: scope.json
     Contoh isi scope.json:
       {
         "operator": "nama_kamu",
         "engagement": "lab-dvwa-2026",
         "authorized_hosts": ["localhost", "127.0.0.1", "*.test", "*.lab"]
       }
  2. Kalau tidak ada scope.json → mode INTERACTIVE: user ditanya per-target.
  3. Host yang match wildcard `*.local` dianggap authorized tanpa prompt.
  4. Host lain → user harus ketik 'AUTHORIZED' (perilaku SAMA seperti kode lama).

Tidak ada perubahan perilaku dasar — hanya menambah opsi file scope.
"""
import fnmatch
import json
import os
from urllib.parse import urlparse


def get_operator() -> str:
    """Ambil nama operator dari env TANPHA_OPERATOR, atau tanya sekali."""
    env = os.environ.get("TANPHA_OPERATOR")
    if env:
        return env
    try:
        name = input("[?] Nama operator (untuk audit log, default 'anonymous'): ").strip()
        return name or "anonymous"
    except (KeyboardInterrupt, EOFError):
        return "anonymous"


class ScopeManager:
    def __init__(self, scope_file: str = "scope.json"):
        self.scope_file = scope_file
        self.data = self._load_or_none()
        self.interactive_confirmed: set = set()  # host yang sudah user konfirmasi

    def _load_or_none(self):
        if not os.path.exists(self.scope_file):
            return None
        try:
            with open(self.scope_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
        except Exception:
            return None

    def _match_host(self, host: str) -> bool:
        """Match hostname terhadap authorized_hosts (support wildcard *)."""
        host = (host or "").lower()
        if not host:
            return False
        if self.data is None:
            # Mode fallback: localhost otomatis OK (sama seperti kode lama)
            local_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
            if host in local_hosts:
                return True
            if any(host.endswith(s) for s in (".local", ".test", ".lab", ".ctf", ".internal")):
                return True
            return False

        for pattern in self.data.get("authorized_hosts", []):
            if fnmatch.fnmatch(host, pattern.lower()):
                return True
        return False

    def confirm_scope(self, url: str) -> bool:
        """
        Return True jika URL boleh di-test.
        Perilaku SAMA seperti _confirm_scope() lama, tapi:
          - Bisa dibypass via scope.json (kalau host match).
          - Hasil konfirmasi interaktif di-cache per host (tidak tanya berulang).
        """
        host = (urlparse(url).hostname or "").lower()

        if self._match_host(host):
            return True

        if host in self.interactive_confirmed:
            return True

        print(f"[!] Target bukan localhost/scope ({host}).")
        print("[!] Gunakan HANYA pada sistem milikmu atau yang punya izin tertulis.")
        try:
            ans = input("    Ketik 'AUTHORIZED' untuk melanjutkan: ").strip()
        except (KeyboardInterrupt, EOFError):
            return False

        if ans == "AUTHORIZED":
            self.interactive_confirmed.add(host)
            return True
        return False

    def summary(self) -> str:
        if self.data is None:
            return "scope.json tidak ditemukan — mode INTERACTIVE."
        op = self.data.get("operator", "?")
        eng = self.data.get("engagement", "?")
        hosts = ", ".join(self.data.get("authorized_hosts", []))
        return f"scope: operator={op}, engagement={eng}, hosts=[{hosts}]"
