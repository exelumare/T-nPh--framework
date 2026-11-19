"""Sensitive File Scanner for TanPha. Finds exposed configs and backups."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence
from core.verification import VerificationResult, VerificationStatus

class SensitiveFilesModule(BaseModule):
    name = "SensitiveFiles"
    module_id = "sensitive_files"
    version = "1.0"
    vulnerability_class = "INFORMATION_DISCLOSURE"

    def __init__(self):
        super().__init__()
        # File-file yang sering bocor di website sekolah/kampus
        self.files_to_check = [
            "config.php", "config.php.bak", ".env", ".git/config", 
            "database.php", "wp-config.php", "backup.zip", "phpinfo.php",
            "db.php", "koneksi.php"
        ]

    def can_run(self, context: TargetContext) -> bool:
        return True

    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []
        base_url = context.target.base_url.rstrip('/') + '/'

        print(f"      [>] Checking for Sensitive Files on: {base_url}")

        for file in self.files_to_check:
            target_url = base_url + file
            res = context.http_client.request("GET", target_url, auth_checker=auth_checker)

            if res and res.success and res.response:
                status = res.response.status_code
                if status == 200 and len(res.response.text) > 0:
                    print(f"          [!] BOCOR: {target_url} (Status: {status})")
                    
                    # Cek isi file untuk mastiin ini beneran bocor
                    text = res.response.text.lower()
                    if "password" in text or "db_pass" in text or "root" in text or "username" in text:
                        print(f"          [🚨] CRITICAL: File {file} contains credential strings!")
                        evidence_pool.append(Evidence(
                            attempt_id=f"sensitive_{file}",
                            module_id=self.module_id, module_version=self.version,
                            location=target_url, parameter="",
                            outcome="OBSERVED", reason_code="EXPOSED_CONFIG",
                            reason_detail=f"File {file} exposed and contains credentials",
                            confidence=0.9, evidence_text="Exposed config", assess_payload=""
                        ))

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "EXPOSED_CONFIG":
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.95, "CONFIG_EXPOSED",
                "Sensitive config file is accessible.",
                verify_payload=""
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")
