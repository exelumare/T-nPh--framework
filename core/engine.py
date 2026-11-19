import time
import logging
from functools import partial
from urllib.parse import urlparse
from core.context import TargetContext, Evidence, Finding
from core.scope import ScopeManager
from discovery.engine import DiscoveryEngine
from discovery.crawler import CrawlerEngine
from fingerprint.engine import FingerprintEngine
from core.verification import VerificationStatus
from core.sequence import SequenceEngine
from core.origin_ip import OriginIPFinder

# --- IMPORT YANG DIPISAH BIAR ANTI CRASH ---
try:
    from reporting.cli import CLIReporter
except ImportError:
    class CLIReporter:
        def generate(self, c): pass

try:
    from reporting.json import JSONReporter
except ImportError:
    class JSONReporter:
        def generate(self, c): pass

try:
    from reporting.html import HTMLReporter
except ImportError:
    class HTMLReporter:
        def generate(self, c): pass

try:
    from reporting.pdf import PDFReporter
except ImportError:
    print("\n[!] WARNING: Modul 'fpdf' belum di-install. Laporan PDF dilewati.")
    class PDFReporter:
        def generate(self, c): pass

logger = logging.getLogger(__name__)

class EngineState:
    START = "START"
    SCOPE_CHECK = "SCOPE_CHECK"
    DISCOVERY = "DISCOVERY"
    SEQUENCE = "SEQUENCE"
    BASELINE = "BASELINE"
    FINGERPRINT = "FINGERPRINT"
    MODULE_SELECTION = "MODULE_SELECTION"
    ASSESSMENT = "ASSESSMENT"
    VALIDATION = "VALIDATION"
    CLASSIFICATION = "CLASSIFICATION"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"

class AutoAssessmentEngine:
    def __init__(self, context: TargetContext, modules, sequence_steps=None, active_modules=None, scope_manager=None):
        self.context = context
        self.modules = modules
        self.sequence_steps = sequence_steps or []
        self.active_modules = active_modules or []
        self.scope = scope_manager if scope_manager else ScopeManager()

        self.discovery = DiscoveryEngine()
        self.crawler = CrawlerEngine(max_depth=1, max_urls=30)
        self.fingerprint = FingerprintEngine()
        self.sequence_engine = SequenceEngine(self.context)
        self.origin_ip_finder = OriginIPFinder(self.context)

        self.cli_reporter = CLIReporter()
        self.json_reporter = JSONReporter()
        self.html_reporter = HTMLReporter()
        self.pdf_reporter = PDFReporter()

        self.state = EngineState.START
        self.evidence_pool = []

    def run(self):
        print("[START] Initializing Engine...")
        self.state = EngineState.SCOPE_CHECK

        print("\n[SCOPE_CHECK] Checking Authorization...")
        initial_checker = partial(self.scope.check, module_id="engine_init")
        if not initial_checker(self.context.target.base_url):
            print("[-] Scope denied. Aborting.")
            return

        self.state = EngineState.DISCOVERY
        print("\n[DISCOVERY] Discovering...")
        try:
            discovery_checker = partial(self.scope.check, module_id="discovery")
            self.discovery.analyze(self.context, discovery_checker)
            self.crawler.crawl(self.context, auth_checker=discovery_checker)
        except Exception as e:
            print(f"[!] Discovery failed: {e}")

        self.state = EngineState.SEQUENCE
        if not self.sequence_steps:
            print("\n[SEQUENCE] Skipped (No sequence provided).")
        else:
            seq_checker = partial(self.scope.check, module_id="sequence")
            self.sequence_engine.execute(self.sequence_steps, auth_checker=seq_checker)

        self.state = EngineState.BASELINE
        print("\n[BASELINE] Sending global baseline...")
        try:
            baseline_checker = partial(self.scope.check, module_id="baseline")
            baseline_res = self.context.http_client.request(
                "GET", self.context.target.base_url, auth_checker=baseline_checker
            )
            if not baseline_res or not baseline_res.response:
                print("[-] Baseline failed.")
                return
        except Exception as e:
            print(f"[-] Baseline failed: {e}")
            return

        self.state = EngineState.FINGERPRINT
        print("\n[FINGERPRINT] Analyzing Baseline for Fingerprints...")
        try:
            self.fingerprint.analyze(self.context, baseline_res.response)
        except Exception as e:
            print(f"[!] Fingerprint failed: {e}")

        try:
            ip_checker = partial(self.scope.check, module_id="origin_ip")
            external_checker = partial(self.scope.check, module_id="external_api")
            origin_ip = self.origin_ip_finder.find(
                self.context.target.base_url,
                auth_checker=ip_checker,
                external_checker=external_checker
            )
            if origin_ip:
                print(f"   [+] Potential Origin IP Found: {origin_ip} -> {self.context.target.base_url}")
                self.evidence_pool.append(Evidence(
                    attempt_id="origin_ip_finding", module_id="origin_ip", module_version="1.0",
                    location=self.context.target.base_url, parameter="", outcome="RECON_SUCCESS",
                    reason_code="ORIGIN_IP_EXPOSED", reason_detail=f"Found {origin_ip}",
                    confidence=0.8, evidence_text=f"Origin IP: {origin_ip}", assess_payload=""
                ))
        except Exception:
            pass

        self.state = EngineState.MODULE_SELECTION
        if not self.active_modules:
            self.active_modules = self.modules
        print(f"\n[MODULE_SELECTION]  -> {len(self.active_modules)} modules selected.")

        self.state = EngineState.ASSESSMENT
        print("\n[ASSESSMENT]")

        endpoints_to_test = self.context.discovery.endpoints

        if not endpoints_to_test:
            endpoints_to_test = [(self.context.target.base_url, "GET", tuple(self.context.discovery.parameters))]

        for endpoint in endpoints_to_test:
            target_url = endpoint[0]
            method = endpoint[1]
            params = list(endpoint[2]) if endpoint[2] else ["id"]

            print(f"\n  [*] Testing Endpoint: {target_url} (Params: {params})")

            original_url = self.context.target.base_url
            original_params = self.context.discovery.parameters
            original_method = self.context.discovery.form_method

            self.context.target.base_url = target_url
            self.context.discovery.parameters = params
            self.context.discovery.form_method = method
            self.context.discovery.form_action = target_url

            for mod in self.active_modules:
                if hasattr(mod, 'can_run'):
                    mod.can_run(self.context)

                mod_checker = partial(self.scope.check, module_id=mod.module_id)
                evs = mod.assess(self.context, mod_checker)
                if evs:
                    self.evidence_pool.extend(evs)

            self.context.target.base_url = original_url
            self.context.discovery.parameters = original_params
            self.context.discovery.form_method = original_method

        self.state = EngineState.VALIDATION
        print("\n[VALIDATION]")
        
        self.context.results.validated = []
        self.context.results.rejected = []
        self.context.results.inconclusive = []
        self.context.results.evidence_pool = self.evidence_pool

        seen_vulns = set() # <--- PENANDA ANTI-DUPLIKAT

        for ev in self.evidence_pool:
            mod = next((m for m in self.active_modules if m.module_id == ev.module_id), None)
            if mod:
                mod_checker = partial(self.scope.check, module_id=mod.module_id)
                res = mod.verify(self.context, ev, mod_checker)

                vuln_class = getattr(mod, 'vulnerability_class', "UNKNOWN_VULN")
                v_status = res.status.value if hasattr(res.status, 'value') else str(res.status)

                if res.status == VerificationStatus.VALIDATED:
                    # Cek duplikat (modul + parameter yang sama)
                    vuln_key = f"{ev.module_id}_{ev.parameter}"
                    if vuln_key in seen_vulns:
                        continue 
                    seen_vulns.add(vuln_key)

                    # Fix Severity Mapping
                    impact = "UNCLASSIFIED"
                    if vuln_class == "SQL_INJECTION": impact = "DATABASE_ACCESS"
                    elif vuln_class == "COMMAND_INJECTION": impact = "REMOTE_CODE_EXECUTION"
                    elif vuln_class == "LOCAL_FILE_INCLUSION": impact = "SENSITIVE_FILE_DISCLOSURE"
                    elif vuln_class == "XSS": impact = "SESSION_HIJACKING"
                    elif vuln_class == "SSRF": impact = "INTERNAL_NETWORK_ACCESS"
                    
                    finding_obj = Finding(
                        module_id=ev.module_id,
                        location=ev.location,
                        parameter=ev.parameter,
                        vulnerability=vuln_class,
                        verification=v_status,
                        impact=impact,
                        privilege=getattr(mod, 'default_privilege', "UNKNOWN"),
                        confidence=res.confidence,
                        evidence=ev.evidence_text,
                        assess_payload=ev.assess_payload,
                        verify_payload=res.verify_payload
                    )
                    self.context.results.validated.append(finding_obj)
                    print(f"      [+] VALIDATED: {vuln_class} on '{ev.parameter}'")
                elif res.status == VerificationStatus.REJECTED:
                    self.context.results.rejected.append(ev)
                else:
                    self.context.results.inconclusive.append(ev)

        print("\n[CLASSIFICATION] Applying Severity/Impact Policy...")
        self.state = EngineState.EXPLOIT
        self.state = EngineState.REPORT
        print("\n[REPORT]")
        print("Generating Reports...")

        # Fix Host Mapping untuk nama file
        if not self.context.target.host or self.context.target.host == "unknown_host":
            parsed_url = urlparse(self.context.target.base_url)
            self.context.target.host = parsed_url.hostname or "127.0.0.1"
        
        try:
            self.cli_reporter.generate(self.context)
        except Exception as e:
            print(f"[!] CLI Report Error: {e}")

        try:
            self.json_reporter.generate(self.context)
        except Exception as e:
            print(f"[!] JSON Report Error: {e}")

        try:
            self.html_reporter.generate(self.context)
        except Exception as e:
            print(f"[!] HTML Report Error: {e}")

        try:
            self.pdf_reporter.generate(self.context)
        except Exception as e:
            print(f"[!] PDF Report Error: {e}")
