"""Sensitive File Scanner for TanPha. Finds exposed configs and backups."""
from urllib.parse import urlparse
from modules.base import BaseModule
from core.context import TargetContext, Evidence
from core.verification import VerificationResult, VerificationStatus


# Marker per tipe file: isi response HARUS mengandung salah satu marker ini
# biar dianggap bocor beneran (bukan halaman SPA/404 fallback).
FILE_MARKERS = {
    "config.php":     ["<?php"],
    "config.php.bak": ["<?php"],
    "database.php":   ["<?php"],
    "db.php":         ["<?php"],
    "koneksi.php":    ["<?php"],
    "wp-config.php":  ["DB_NAME", "DB_USER", "AUTH_KEY", "table_prefix"],
    ".env":           ["APP_KEY=", "DB_PASSWORD=", "DB_USERNAME=", "SECRET=", "API_KEY="],
    ".git/config":    ["[core]", "repositoryformatversion", "[remote"],
    "phpinfo.php":    ["PHP Version", "PHP License", "phpinfo()", "php.ini"],
    "backup.zip":     [b"PK\x03\x04"],  # zip magic bytes
}

# Kata yang menandakan credentials beneran di dalam file konfigurasi.
CREDENTIAL_PATTERNS = [
    "password=", "password:", "passwd=", "pwd=",
    "db_password", "db_pass", "db_user", "db_name",
    "secret_key", "api_key", "apikey", "access_token",
    "private_key", "auth_key", "root:",
]


class SensitiveFilesModule(BaseModule):
    name = "SensitiveFiles"
    module_id = "sensitive_files"
    version = "1.1"
    vulnerability_class = "INFORMATION_DISCLOSURE"

    def __init__(self):
        super().__init__()
        self.files_to_check = [
            "config.php", "config.php.bak", ".env", ".git/config",
            "database.php", "wp-config.php", "backup.zip", "phpinfo.php",
            "db.php", "koneksi.php"
        ]

    def can_run(self, context: TargetContext) -> bool:
        return True

    # ── URL helpers ──────────────────────────────────────────────
    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _path_dir(url: str) -> str:
        """Buang query & filename. 
        /benchmark/cmdi-00/BenchmarkTest00406.html?x=y -> /benchmark/cmdi-00"""
        p = urlparse(url)
        path = p.path.rsplit("/", 1)[0]
        return f"{p.scheme}://{p.netloc}{path}"

    def _filename_from_url(self, url: str) -> str:
        for f in self.files_to_check:
            if url.endswith("/" + f):
                return f
        return url.rsplit("/", 1)[-1]

    # ── Content validation ───────────────────────────────────────
    @staticmethod
    def _matches_file_signature(filename: str, content_bytes: bytes, body_text: str) -> bool:
        markers = FILE_MARKERS.get(filename, [])
        if not markers:
            return True  # tipe file tak dikenal -> lolos (jarang kejadian)
        if filename.endswith(".zip"):
            return any(m in content_bytes[:200] for m in markers if isinstance(m, bytes))
        return any(m in body_text for m in markers if isinstance(m, str))

    @staticmethod
    def _contains_credentials(text: str) -> bool:
        low = text.lower()
        return any(pat in low for pat in CREDENTIAL_PATTERNS)

    # ── Main assessment ──────────────────────────────────────────
    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []
        page_url = context.target.base_url

        # Kandidat base: origin (https://host/) dan direktori halaman
        # (/benchmark/cmdi-00/). Query string otomatis terbuang.
        candidate_bases = []
        for b in (self._origin(page_url), self._path_dir(page_url)):
            if b and b not in candidate_bases:
                candidate_bases.append(b)

        for base in candidate_bases:
            base = base.rstrip("/") + "/"
            print(f"      [>] Checking for Sensitive Files on: {base}")

            for file in self.files_to_check:
                target_url = base + file
                res = context.http_client.request("GET", target_url, auth_checker=auth_checker)

                if not (res and res.success and res.response):
                    continue
                if res.response.status_code != 200:
                    continue

                body = res.response.text or ""
                content_bytes = res.response.content or b""
                if len(body) == 0 and len(content_bytes) == 0:
                    continue

                # FILTER #1: isi response harus match signature file yang diharapkan.
                # Kalau server balikin halaman HTML benchmark untuk path /config.php,
                # filter ini yang nolak.
                if not self._matches_file_signature(file, content_bytes, body):
                    continue

                # FILTER #2: cek apakah ada credentials beneran di dalamnya.
                has_creds = self._contains_credentials(body)

                print(f"          [!] BOCOR: {target_url} (Status: 200)")
                if has_creds:
                    print(f"          [🚨] CRITICAL: File {file} contains credential strings!")

                evidence_pool.append(Evidence(
                    attempt_id=f"sensitive_{file}",
                    module_id=self.module_id, module_version=self.version,
                    location=target_url, parameter="",
                    outcome="OBSERVED",
                    reason_code="EXPOSED_CONFIG_WITH_CREDS" if has_creds else "EXPOSED_CONFIG",
                    reason_detail=f"File {file} exposed"
                                  + (" with credentials" if has_creds else ""),
                    confidence=0.9 if has_creds else 0.6,
                    evidence_text="Exposed file", assess_payload=""
                ))

        return evidence_pool

    # ── Verification ─────────────────────────────────────────────
    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code not in ("EXPOSED_CONFIG", "EXPOSED_CONFIG_WITH_CREDS"):
            return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")

        # Re-fetch untuk konfirmasi masih exposed & konten sesuai.
        res = context.http_client.request("GET", evidence.location, auth_checker=auth_checker)
        if not (res and res.success and res.response and res.response.status_code == 200):
            return VerificationResult(
                VerificationStatus.REJECTED, 0.0, "UNREACHABLE",
                "Not accessible on re-check"
            )

        body = res.response.text or ""
        content_bytes = res.response.content or b""
        filename = self._filename_from_url(evidence.location)

        if not self._matches_file_signature(filename, content_bytes, body):
            return VerificationResult(
                VerificationStatus.REJECTED, 0.0, "CONTENT_MISMATCH",
                "Content does not match expected file signature"
            )

        return VerificationResult(
            VerificationStatus.VALIDATED, evidence.confidence,
            "FILE_EXPOSED",
            "Re-verified: sensitive file accessible with expected signature.",
            verify_payload=""
        )
