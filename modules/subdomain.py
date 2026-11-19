"""Subdomain Enumeration & Wildcard Detection Module for TanPha."""
import socket
import random
import string
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus

class SubdomainModule(BaseModule):
    name = "SubdomainEnumeration"
    module_id = "subdomain"
    version = "1.1 (Wildcard Detection)"
    vulnerability_class = "RECONNAISSANCE"

    def __init__(self):
        super().__init__()
        # Wordlist dasar (lu bisa tambahin sendiri)
        self.wordlist = [
            "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
            "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
            "wiki", "web", "media", "email", "images", "img", "www1", "intranet", "portal",
            "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
            "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
            "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
            "info", "apps", "download", "remote", "db", "forums", "store", "relay",
            "files", "newsletter", "app", "live", "owa", "en", "start", "sms", "office",
            "exchange", "ipv4"
        ]

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _get_ip(self, domain):
        """Resolve domain to IP."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _check_wildcard(self, domain):
        """Cek apakah target make Wildcard DNS."""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        test_domain = f"{random_str}.{domain}"
        ip = self._get_ip(test_domain)
        return ip

    def _check_subdomain(self, sub, domain):
        full_domain = f"{sub}.{domain}"
        ip = self._get_ip(full_domain)
        return (full_domain, ip)

    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []
        parsed = context.target.base_url.split("//")[-1].split("/")[0]
        domain = parsed.split(":")[0] # Hapus port kalau ada
        print(f"      [>] Starting DNS Brute-Force on '{domain}'...")

        # 1. Cek Wildcard DNS
        wildcard_ip = self._check_wildcard(domain)
        if wildcard_ip:
            print(f"          [!] WILDCARD DNS DETECTED: Resolves to {wildcard_ip}")
            print(f"          [!] TànPhá akan memfilter IP ini dari hasil.")
        else:
            print(f"          [+] No Wildcard DNS detected. Results will be accurate.")

        found_subdomains = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self._check_subdomain, sub, domain) for sub in self.wordlist]
            for future in futures:
                full_domain, ip = future.result()
                if ip:
                    # FILTERING WILDCARD
                    if wildcard_ip and ip == wildcard_ip:
                        continue # Skip, ini false positive
                    
                    print(f"          [+] Found: {full_domain} -> {ip}")
                    found_subdomains.append((full_domain, ip))

        if not found_subdomains:
            print(f"          [-] No valid subdomains found (after wildcard filtering).")
            return evidence_pool

        print(f"\n      [+] TOTAL Found {len(found_subdomains)} unique valid subdomains!")
        evidence_pool.append(Evidence(
            attempt_id="subdomain_recon",
            module_id=self.module_id, module_version=self.version,
            location=context.target.base_url, parameter="",
            outcome="RECON_SUCCESS", reason_code="SUBDOMAIN_FOUND",
            reason_detail=f"Found {len(found_subdomains)} subdomains",
            confidence=0.8, evidence_text="Subdomains found", assess_payload=json.dumps(found_subdomains)
        ))
        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "SUBDOMAIN_FOUND":
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.8, "RECON_ONLY",
                "Subdomains found during reconnaissance.",
                verify_payload=""
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")
