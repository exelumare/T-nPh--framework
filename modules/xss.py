"""XSS Module for TanPha V4.0 (Multi-Vector + Ultimate Sanity Check)."""
import time
import json
import html
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from core.ai_router import AIRouter

class XSSModule(BaseModule):
    name = "CrossSiteScripting"
    module_id = "xss"
    version = "4.0 (Multi-Vector + AI Sanity)"
    vulnerability_class = "XSS"
    default_impact = "SESSION_HIJACKING"
    default_privilege = "USER"

    COMMON_INJECTABLE_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For", "X-Original-URL",
        "Accept-Language", "Cookie"
    ]
    POST_BODY = {"Submit": "Submit", "answer": "answer"}

    def __init__(self):
        super().__init__()
        self.ai = AIRouter()

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            context.discovery.parameters = ["q"]
        return True

    @staticmethod
    def _servlet_url(url: str) -> str:
        p = urlparse(url)
        path = p.path
        if path.endswith(".html"):
            path = path[:-5]
        return f"{p.scheme}://{p.netloc}{path}"

    def _get_submit_field(self, context):
        for p in context.discovery.parameters:
            if any(k in p.lower() for k in ["submit", "login", "go", "send", "btn", "save", "search"]):
                return p
        return "Submit"

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, v + payload) if k == param else (k, v) for k, v in qs]
        if not new_qs: new_qs = [(param, payload)]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="<>\"'()/=")))

    def _send_payload(self, context, param, payload, auth_checker=None, timeout=10):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            res = context.http_client.request(
                "GET", target_url, target_param=param,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
            return res.response if res and res.response is not None else None
        else:
            submit_field = self._get_submit_field(context)
            data = {param: payload, submit_field: "Submit"}
            res = context.http_client.request(
                "POST", context.target.base_url, data=data,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
            return res.response if res and res.response is not None else None

    def _send_header_payload(self, context, header_name, payload, auth_checker=None, timeout=10, method="GET"):
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

    def _send_cookie_payload(self, context, cookie_name, payload, auth_checker=None, timeout=10, method="GET"):
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

    def _test_xss(self, context, param, sender_func, injection_point="PARAM"):
        marker = "TANPHA_XSS_7331"
        payloads = [
            {"payload": f"<script>alert('{marker}')</script>", "desc": "Basic Script"},
            {"payload": f"<img src=x onerror=alert('{marker}')>", "desc": "Img Onerror"},
            {"payload": f"<svg/onload=alert('{marker}')>", "desc": "SVG Onload"}
        ]

        baseline_res = sender_func("test")
        baseline_text = baseline_res.text if baseline_res else ""
        baseline_len = len(baseline_text)
        baseline_status = baseline_res.status_code if baseline_res else 200

        for item in payloads:
            res = sender_func(item["payload"])
            if res is not None:
                res_text = res.text
                res_len = len(res_text)
                res_status = res.status_code

                # 1. CEK REFLECTED XSS (PAYLOAD MUNCUL MENTAH)
                if item["payload"] in res_text:
                    print(f"      [!!] Reflected XSS on '{param}' via {injection_point} ({item['desc']})!")
                    return Evidence(
                        attempt_id=f"xss_reflect_{injection_point.lower()}", 
                        module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="CHANGED_RESPONSE",
                        reason_code="REFLECTED_XSS", reason_detail=f"Payload '{item['desc']}' reflected raw",
                        confidence=0.95, evidence_text=f"Payload: {item['payload']}", assess_payload=item["payload"]
                    )

                # 2. ZERO-SIGNATURE ANOMALY CHECK
                is_suspicious = (res_status >= 500 or res_status != baseline_status or abs(res_len - baseline_len) > 50)

                # 3. PANGGIL AI DENGAN SANITY CHECK
                if is_suspicious:
                    print(f"      [!] Suspicious change on '{param}' ({injection_point})! Asking AI...")
                    try:
                        ai_answer = self.ai.analyze(modul_name="XSS", payload=item["payload"], baseline_text=baseline_text, current_text=res_text)
                        clean_json = ai_answer.replace("```json", "").replace("```", "").strip()
                        
                        start_idx = clean_json.find('{')
                        end_idx = clean_json.rfind('}')
                        if start_idx != -1 and end_idx != -1:
                            clean_json = clean_json[start_idx:end_idx+1]

                        ai_data = json.loads(clean_json)
                        is_vuln = ai_data.get("is_vulnerable", False)
                        vuln_type = ai_data.get("vulnerability_type", "NONE").upper()

                        if is_vuln:
                            if vuln_type == "XSS":
                                print("          [-] SANITY CHECK: AI said XSS, but payload is not raw. Ignoring False Positive.")
                                continue
                            elif vuln_type != "NONE":
                                print(f"          [+] AI detected {vuln_type} anomaly. Pivot!")
                                return Evidence(
                                    attempt_id=f"xss_anomaly_{injection_point.lower()}", module_id=self.module_id, module_version=self.version,
                                    location=context.target.base_url, parameter=param, outcome="ANOMALY",
                                    reason_code="AI_PIVOT", reason_detail=clean_json,
                                    confidence=0.7, evidence_text=f"Suspicious response change", assess_payload=item["payload"]
                                )
                        else:
                            print("          [-] AI said False Positive. Skipping.")
                            break

                    except Exception as e:
                        print(f"          [-] AI Error parsing JSON: {e}")
        return None

    def assess(self, context: TargetContext, auth_checker=None) -> list[Evidence]:
        evidence_pool = []

        # 1. Parameters (GET / POST)
        for param in context.discovery.parameters:
            print(f"      [>] Testing XSS on param '{param}'...")
            sender = lambda p: self._send_payload(context, param, p, auth_checker)
            ev = self._test_xss(context, param, sender, "PARAM")
            if ev:
                evidence_pool.append(ev)
                continue

        # 2. Headers
        headers_to_test = list(context.discovery.parameters)
        headers_to_test.extend(self.COMMON_INJECTABLE_HEADERS)
        seen = set()
        headers_to_test = [x for x in headers_to_test if not (x.lower() in seen or seen.add(x.lower()))]

        print(f"      [>] Testing XSS via {len(headers_to_test)} headers (GET+POST)...")
        for header_name in headers_to_test:
            ev_found = False
            for method in ("GET", "POST"):
                sender = lambda p, h=header_name, m=method: self._send_header_payload(context, h, p, auth_checker, method=m)
                ev = self._test_xss(context, header_name, sender, "HEADER")
                if ev:
                    evidence_pool.append(ev)
                    ev_found = True
                    break
            if ev_found:
                print(f"      [+] Stop testing more headers, found vuln in '{header_name}'.")
                break

        # 3. Cookies
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

        print(f"      [>] Testing XSS via {len(cookie_names)} cookies (GET+POST)...")
        for cookie_name in cookie_names:
            ev_found = False
            for method in ("GET", "POST"):
                sender = lambda p, c=cookie_name, m=method: self._send_cookie_payload(context, c, p, auth_checker, method=m)
                ev = self._test_xss(context, cookie_name, sender, "COOKIE")
                if ev:
                    evidence_pool.append(ev)
                    ev_found = True
                    break
            if ev_found:
                print(f"      [+] Stop testing more cookies, found vuln in '{cookie_name}'.")
                break

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "REFLECTED_XSS":
            point = evidence.attempt_id.lower()
            if "header" in point:
                res = self._send_header_payload(context, evidence.parameter, evidence.assess_payload, auth_checker)
            elif "cookie" in point:
                res = self._send_cookie_payload(context, evidence.parameter, evidence.assess_payload, auth_checker)
            else:
                res = self._send_payload(context, evidence.parameter, evidence.assess_payload, auth_checker)
                
            if res and res.text and evidence.assess_payload in res.text:
                return VerificationResult(VerificationStatus.VALIDATED, 0.95, "XSS_CONFIRMED", "Payload reflected.", verify_payload=evidence.assess_payload)
        elif evidence.reason_code == "AI_PIVOT":
            return VerificationResult(VerificationStatus.VALIDATED, 0.8, "AI_VALIDATED", "AI Hydra confirmed the anomaly.", verify_payload=evidence.assess_payload)

        return VerificationResult(VerificationStatus.REJECTED, 0.0, "XSS_FAILED", "Payload not reflected.")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] XSS EXPLOITATION INFO [***]")
        print(f"[*] Target URL : {finding.location}")
        print(f"[*] Vulnerable Parameter : {finding.parameter}")
        print(f"[*] Type : {finding.vulnerability}")
        print(f"[*] Payload : {finding.verify_payload}")
