from urllib.parse import urlparse, parse_qsl, urljoin
from core.context import TargetContext
from typing import Callable, Optional
import re


class DiscoveryEngine:
    def analyze(self, context: TargetContext, scope_checker: Optional[Callable[[str], bool]] = None):
        target_url = context.target.base_url
        parsed = urlparse(target_url)
        
        # 1. Cek GET parameter dulu
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if params:
            context.discovery.parameters = [k for k, v in params]
            print(f"   [+] Discovered {len(context.discovery.parameters)} GET parameters: {context.discovery.parameters}")
            return
        
        # 2. Kalau nggak ada, parse form HTML (buat POST / Multi-Step)
        print("   [*] No GET parameters. Attempting Form Discovery...")
        try:
            res = context.http_client.request("GET", target_url, scope_checker=scope_checker)
            if res.success and res.response:
                html = res.response.text
                
                with open("debug.html", "w") as f:
                    f.write(html)
                
                # === V4.1 SUPER LONGGAR REGEX ===
                # Ambil SEMUA tag <input>, <select>, <textarea> yang punya atribut 'name'
                inputs = re.findall(r'<(?:input|select|textarea)[^>]*name=["\']?([^"\'\s>]+)["\']?', html, re.IGNORECASE)
                
                # Ambil Form Action & Method
                form_match = re.search(r'<form[^>]*>', html, re.IGNORECASE)
                if form_match:
                    form_tag = form_match.group(0)
                    action_match = re.search(r'action=["\']?([^"\'\s>]*)["\']?', form_tag, re.IGNORECASE)
                    method_match = re.search(r'method=["\']?([^"\'\s>]+)["\']?', form_tag, re.IGNORECASE)
                    
                    action = action_match.group(1) if action_match else ""
                    method = method_match.group(1).upper() if method_match else "POST"
                    
                    context.discovery.form_action = urljoin(target_url, action) if action else target_url
                    context.discovery.form_method = method
                    print(f"   [DEBUG] Form Action: {context.discovery.form_action} | Method: {method}")
                else:
                    context.discovery.form_action = target_url
                    context.discovery.form_method = "POST"

                # Filter parameter sampah
                params_found = []
                for p in dict.fromkeys(inputs):
                    if not any(x in p.lower() for x in ["token", "submit", "btn", "button"]):
                        params_found.append(p)
                
                context.discovery.parameters = params_found
                print(f"   [+] Discovered parameters: {params_found}")
                    
        except Exception as e:
            print(f"   [-] Form Discovery failed: {e}")
