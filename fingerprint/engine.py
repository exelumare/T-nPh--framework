from core.context import TargetContext
from typing import Callable, Optional

class FingerprintEngine:
    def analyze(self, context: TargetContext, scope_checker: Optional[Callable[[str], bool]] = None):
        headers = context.baseline.headers
        server = headers.get("Server", "Unknown")
        context.fingerprint.server = server
        
        powered_by = headers.get("X-Powered-By", "")
        if "PHP" in powered_by: context.fingerprint.framework = "PHP"
        elif "ASP.NET" in powered_by: context.fingerprint.framework = "ASP.NET"
        elif "Express" in powered_by: context.fingerprint.framework = "Node.js (Express)"
        else: context.fingerprint.framework = "Unknown"
            
        print(f"   [+] Server: {context.fingerprint.server} | Framework: {context.fingerprint.framework}")
