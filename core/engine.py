import sys
from enum import Enum
from core.context import TargetContext, Finding
from core.scope import ScopeManager
from discovery.engine import DiscoveryEngine
from fingerprint.engine import FingerprintEngine
from reporting.cli import CLIReporter
from reporting.json import JSONReporter
from core.verification import VerificationStatus
from urllib.parse import urlparse

class EngineState(Enum):
    START = "START"
    SCOPE_CHECK = "SCOPE_CHECK"
    DISCOVERY = "DISCOVERY"
    BASELINE = "BASELINE"
    FINGERPRINT = "FINGERPRINT"
    MODULE_SELECTION = "MODULE_SELECTION"
    ASSESSMENT = "ASSESSMENT"
    VALIDATION = "VALIDATION"
    CLASSIFICATION = "CLASSIFICATION"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"
    END = "END"

class AutoAssessmentEngine:
    def __init__(self, context: TargetContext, modules: list):
        self.context = context
        self.modules = modules
        self.active_modules = []
        self.scope = ScopeManager()
        self.discovery = DiscoveryEngine()
        self.fingerprint = FingerprintEngine()
        self.cli_reporter = CLIReporter()
        self.json_reporter = JSONReporter()
        self.state = EngineState.START

    def run(self):
        self.context.results.evidence_pool.clear()
        self.context.results.validated.clear()
        self.context.results.rejected.clear()
        self.context.results.inconclusive.clear()
        self.context.results.skipped.clear()
        self.state = EngineState.START

        while self.state != EngineState.END:
            print(f"\n[{self.state.value}] ", end="")
            
            if self.state == EngineState.START:
                print("Initializing Engine...")
                if self.context.target.base_url and not self.context.target.host:
                    parsed = urlparse(self.context.target.base_url)
                    self.context.target.host = parsed.hostname or "unknown_host"
                    self.context.target.scheme = parsed.scheme or "http"
                self.state = EngineState.SCOPE_CHECK
                
            elif self.state == EngineState.SCOPE_CHECK:
                print("Checking Authorization...")
                if not self.scope.confirm_scope(self.context.target.base_url):
                    print("[-] Scope denied. Aborting.")
                    self.state = EngineState.END
                else:
                    self.state = EngineState.DISCOVERY
                
            elif self.state == EngineState.DISCOVERY:
                print("Discovering...")
                try:
                    self.discovery.analyze(self.context, scope_checker=self.scope.is_in_scope)
                except Exception as e:
                    print(f"\n[!] Discovery failed: {e}")
                self.state = EngineState.BASELINE
                
            elif self.state == EngineState.BASELINE:
                print("Sending global baseline...")
                result = self.context.http_client.request("GET", self.context.target.base_url, scope_checker=self.scope.is_in_scope)
                if result.success:
                    self.context.baseline.status_code = result.response.status_code
                    self.context.baseline.headers = dict(result.response.headers)
                    self.state = EngineState.FINGERPRINT
                else:
                    reason = result.retry_reason or (str(result.error) if result.error else 'unknown')
                    print(f"[-] Baseline failed: {reason}")
                    self.state = EngineState.END

            elif self.state == EngineState.FINGERPRINT:
                print("Analyzing Baseline for Fingerprints...")
                try:
                    self.fingerprint.analyze(self.context, scope_checker=self.scope.is_in_scope)
                except Exception as e:
                    print(f"\n[!] Fingerprint failed: {e}")
                self.state = EngineState.MODULE_SELECTION
                
            elif self.state == EngineState.MODULE_SELECTION:
                self.active_modules = [m for m in self.modules if m.can_run(self.context)]
                print(f" -> {len(self.active_modules)} modules selected.")
                self.state = EngineState.ASSESSMENT
                
            elif self.state == EngineState.ASSESSMENT:
                for module in self.active_modules:
                    try: 
                        ev_list = module.assess(self.context, scope_checker=self.scope.is_in_scope)
                        if ev_list: 
                            self.context.results.evidence_pool.extend(ev_list)
                    except Exception as e:
                        print(f"\n[!] Error in module {module.name} (assess): {e}")
                self.state = EngineState.VALIDATION
                
            elif self.state == EngineState.VALIDATION:
                status_by_key = {}
                for ev in self.context.results.evidence_pool:
                    key = (ev.module_id, ev.parameter)
                    
                    if key in status_by_key and status_by_key[key] != "INCONCLUSIVE":
                        self.context.results.skipped.append(ev)
                        continue
                        
                    module = next((m for m in self.active_modules if m.module_id == ev.module_id), None)
                    if module:
                        try: 
                            res = module.verify(self.context, ev, scope_checker=self.scope.is_in_scope)
                            status_by_key[key] = res.status.value
                            
                            if res.status == VerificationStatus.VALIDATED:
                                finding = Finding(
                                    module_id=ev.module_id, location=ev.location,
                                    parameter=ev.parameter, vulnerability=module.vulnerability_class,
                                    verification=res.status.value, confidence=res.confidence,
                                    evidence=ev.evidence_text, 
                                    assess_payload=ev.assess_payload,
                                    verify_payload=res.verify_payload
                                )
                                self.context.results.validated.append(finding)
                            elif res.status == VerificationStatus.REJECTED:
                                self.context.results.rejected.append(ev)
                            else:
                                self.context.results.inconclusive.append(ev)
                        except Exception as e:
                            print(f"\n[!] Error in module {module.name} (verify): {e}")
                            status_by_key[key] = "INCONCLUSIVE"
                            self.context.results.inconclusive.append(ev)
                self.state = EngineState.CLASSIFICATION

            elif self.state == EngineState.CLASSIFICATION:
                print("Applying Severity/Impact Policy...")
                for finding in self.context.results.validated:
                    module = next((m for m in self.active_modules if m.module_id == finding.module_id), None)
                    if module:
                        finding.impact = module.default_impact
                        finding.privilege = module.default_privilege
                self.state = EngineState.EXPLOIT

            elif self.state == EngineState.EXPLOIT:
                if not self.context.results.validated:
                    self.state = EngineState.REPORT
                    continue
                
                print(f"Found {len(self.context.results.validated)} validated vulnerabilities.")
                if sys.stdin.isatty():
                    ans = input("Do you want to drop into an interactive shell? (y/n): ").strip().lower()
                else:
                    print("[*] Non-interactive environment detected. Skipping exploit.")
                    ans = 'n'
                
                if ans == 'y':
                    for finding in self.context.results.validated:
                        module = next((m for m in self.active_modules if m.module_id == finding.module_id), None)
                        if module:
                            try:
                                module.exploit(self.context, finding)
                            except Exception as e:
                                print(f"[-] Exploit error: {e}")
                self.state = EngineState.REPORT
                
            elif self.state == EngineState.REPORT:
                print("\nGenerating Reports...")
                self.cli_reporter.generate(self.context)
                self.json_reporter.generate(self.context)
                self.state = EngineState.END
                
            else:
                raise RuntimeError(f"Unhandled engine state: {self.state}")
