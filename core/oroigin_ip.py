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
        try:
            main_ip = socket.gethostbyname(self.domain)
            headers = self.context.baseline.headers
            
            if not self._is_cloudflare(headers, main_ip):
                return None
            
            print("      [!] Cloudflare detected. Attempting Origin IP Discovery...")
            
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            # V5 FIX: Naikin timeout jadi 30 detik
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 200:
                    return None
                data = json.loads(response.read().decode('utf-8'))
                
                subdomains = set()
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub.endswith(self.domain):
                            subdomains.add(sub)
            
            found_ips = []
            for sub in subdomains:
                try:
                    ip = socket.gethostbyname(sub)
                    if ip != main_ip and not self._is_cloudflare({}, ip):
                        found_ips.append((sub, ip))
                except Exception:
                    continue
                    
            return found_ips
            
        except Exception as e:
            print(f"      [-] Origin IP Discovery failed: {e}")
            return None
