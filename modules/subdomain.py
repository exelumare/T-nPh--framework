"""Subdomain Enumeration Module for TanPha V4 (Global Recon)."""
import json
import urllib.request
import urllib.error
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse


class SubdomainModule(BaseModule):
    name = "SubdomainEnumeration"
    module_id = "subdomain"
    version = "1.0 (Global Recon)"
    vulnerability_class = "RECON"
    default_impact = "INFORMATION_DISCLOSURE"
    default_privilege = "NONE"

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        domain = parsed.netloc
        if ":" in domain:
            domain = domain.split(":")[0] # Buang port
        return domain

    def assess(self, context: TargetContext, scope_checker=None) -> list[Evidence]:
        domain = self._extract_domain(context.target.base_url)
        if not domain or domain == "127.0.0.1" or domain.startswith("192.168."):
            print(f"      [-] Target is IP or Localhost. Subdomain Enumeration skipped.")
            return []

        print(f"      [>] Querying crt.sh for subdomains of '{domain}'...")
        
        subdomains = set()
        try:
            # Gunakan API crt.sh
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (TanPha V4)'})
            
            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # crt.sh kadang ngasih multiple domain dipisah newline
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            # Pastiin subdomain valid dan nggak ada wildcard (*)
                            if sub and "*" not in sub and sub.endswith(domain):
                                subdomains.add(sub)
        except urllib.error.URLError as e:
            print(f"      [-] Failed to reach crt.sh: {e.reason}")
            return []
        except Exception as e:
            print(f"      [-] Error parsing crt.sh response: {e}")
            return []

        if subdomains:
            print(f"      [+] Found {len(subdomains)} unique subdomains!")
            # Ambil 10 sample buat ditampilin di evidence
            sample_subs = list(subdomains)[:10]
            evidence_text = f"Found {len(subdomains)} subdomains. Sample: {', '.join(sample_subs)}"
            
            return [Evidence(
                attempt_id="subdomain_enum", module_id=self.module_id, module_version=self.version,
                location=context.target.base_url, parameter="N/A", outcome="CHANGED_RESPONSE",
                reason_code="SUBDOMAIN_FOUND", reason_detail=evidence_text,
                confidence=1.0, evidence_text=evidence_text, assess_payload="N/A"
            )]
        else:
            print(f"      [-] No subdomains found for '{domain}'.")
            return []

    def verify(self, context: TargetContext, evidence: Evidence, scope_checker=None) -> VerificationResult:
        # Subdomain enum selalu valid karena datanya dari API resmi (crt.sh)
        return VerificationResult(
            VerificationStatus.VALIDATED, 1.0, "RECON_CONFIRMED", 
            evidence.reason_detail, verify_payload="N/A"
        )

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] SUBDOMAIN RECON INFO [***]")
        print(f"[*] Target Base : {finding.location}")
        print(f"[*] Result : {finding.reason_detail}")
        print("\n[!] Next step: Scan these subdomains individually to find hidden endpoints.")
