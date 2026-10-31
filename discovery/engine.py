from urllib.parse import urlparse, parse_qsl
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
        
        # 2. Kalau nggak ada, parse form HTML (buat POST)
        print("   [*] No GET parameters. Attempting Form Discovery...")
        try:
            res = context.http_client.request("GET", target_url, scope_checker=scope_checker)
            if res.success and res.response:
                print(f"   [DEBUG] HTTP Status: {res.response.status_code}")
                print(f"   [DEBUG] Response Length: {len(res.response.text)} chars")
                
                # Simpan HTML-nya ke file biar bisa lu baca
                with open("debug.html", "w") as f:
                    f.write(res.response.text)
                print("   [DEBUG] Saved HTML to: debug.html")
                
                # Cek manual string-nya ada atau nggak
                if 'name="id"' in res.response.text:
                    print('   [DEBUG] String name="id" FOUND')
                elif "name='id'" in res.response.text:
                    print("   [DEBUG] String name='id' FOUND")
                else:
                    print('   [DEBUG] String "id" NOT FOUND in HTML')
                    
                # Regex yang lebih longgar
                inputs = re.findall(r'name\s*=\s*["\']?([^"\'\s>]+)["\']?', res.response.text, re.IGNORECASE | re.DOTALL)
                print(f"   [DEBUG] Raw matches: {inputs}")
                
                params_found = [p for p in dict.fromkeys(inputs) if "token" not in p.lower() and "submit" not in p.lower()]
                context.discovery.parameters = params_found
                print(f"   [+] Discovered {len(params_found)} form fields: {params_found}")
        except Exception as e:
            print(f"   [-] Form Discovery failed: {e}")
