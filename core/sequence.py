import re
from typing import Dict, Any

class SequenceStep:
    """Satu langkah dalam urutan serangan (Macro)."""
    def __init__(self, name: str, method: str, url: str, data: Dict[str, str] = None, extract_vars: Dict[str, str] = None):
        self.name = name
        self.method = method.upper()
        self.url = url
        self.data = data or {}
        self.extract_vars = extract_vars or {} # Regex buat nyari token di response

class SequenceEngine:
    """Mesin buat ngejalanin urutan Multi-Step."""
    def __init__(self, context):
        self.context = context

    def execute(self, steps: list[SequenceStep]):
        print("\n[*] Executing Multi-Step Sequence...")
        for step in steps:
            print(f"    [>] Step: {step.name}")
            
            # 1. Ganti value di data pakai session_state kalau ada (misal {{csrf_token}})
            data_to_send = dict(step.data)
            for key, val in data_to_send.items():
                if isinstance(val, str) and val.startswith("{{") and val.endswith("}}"):
                    var_name = val[2:-2]
                    data_to_send[key] = self.context.session_state.get(var_name, "")
            
            # 2. Kirim Request
            if step.method == "GET":
                res = self.context.http_client.request("GET", step.url, scope_checker=None, bypass_mutation=True)
            else:
                res = self.context.http_client.request("POST", step.url, data=data_to_send, scope_checker=None, bypass_mutation=True)
            
            if not res.success:
                print(f"    [-] Step failed: {res.error}")
                return False
            
            # 3. Extract variables (buat step selanjutnya)
            for var_name, regex in step.extract_vars.items():
                match = re.search(regex, res.response.text)
                if match:
                    self.context.session_state[var_name] = match.group(1)
                    print(f"        [+] Extracted {var_name}: {match.group(1)[:10]}...")
                else:
                    print(f"        [-] Failed to extract {var_name}")
                    
        print("[+] Sequence completed successfully.\n")
        return True
