"""WAF Evasion Level 3 Logic: Origin IP Discovery via crt.sh."""
import socket
import json
import urllib.request
from urllib.parse import urlparse

class OriginIPFinder:
    def __init__(self, context):
        self.context = context
        self.domain = context.target.host

    def _is_cloudflare(self, headers, ip):
        if headers and ("cloudflare" in str(headers).lower() or "cf-ray" in headers):
            return True
        if ip.startswith(("104.", "172.67.", "172.68.", "188.114.")):
            return True
        return False

    def find(self):
        """Cari Origin IP dari subdomain via crt.sh."""
        try:
            main_ip = socket.gethostbyname(self.domain)
            headers = self.context.baseline.headers
            
            # 1. Cek apakah pakai Cloudflare
            if not self._is_cloudflare(headers, main_ip):
                return None
            
            print("      [!] Cloudflare detected. Attempting Origin IP Discovery...")
            
            # 2. Query crt.sh
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status != 200:
                    return None
                data = json.loads(response.read().decode('utf-8'))
                
                subdomains = set()
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub.endswith(self.domain):
                            subdomains.add(sub)
            
            # 3. Resolve IP
            found_ips = []
            for sub in subdomains:
                try:
                    ip = socket.gethostbyname(sub)
                    # Kalau IP beda dari Cloudflare & bukan range Cloudflare
                    if ip != main_ip and not self._is_cloudflare({}, ip):
                        found_ips.append((sub, ip))
                except Exception:
                    continue
                    
            return found_ips
            
        except Exception as e:
            return None
