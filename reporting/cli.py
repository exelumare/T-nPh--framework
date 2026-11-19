from core.context import TargetContext

class CLIReporter:
    def generate(self, context: TargetContext):
        width = 63 
        print("\n" + "╔" + "═" * width + "╗")
        print("║" + " " * 22 + "SCAN RESULTS" + " " * 23 + "║")
        print("╠" + "═" * width + "╣")
        
        url = context.target.base_url
        url_display = url if len(url) <= 50 else url[:47] + "..."
        print(f"║ Target URL : {url_display:<49} ║")
        print(f"║ Server     : {context.fingerprint.server:<49} ║")
        print(f"║ Framework  : {context.fingerprint.framework:<49} ║")
        print("╠" + "═" * width + "╣")
        
        total_val = len(context.results.validated)
        total_rej = len(context.results.rejected)
        total_inc = len(context.results.inconclusive)
        total_skip = len(context.results.skipped)
        
        print(f"║ Validated    : {total_val:<40} ║")
        print(f"║ Rejected     : {total_rej:<40} ║")
        print(f"║ Inconclusive : {total_inc:<40} ║")
        print(f"║ Skipped      : {total_skip:<40} ║")
        print("╠" + "═" * width + "╣")
        
        if total_val == 0:
            print("║  No validated vulnerabilities detected.              ║")
        else:
            for i, finding in enumerate(context.results.validated):
                print(f"║ [{i+1}] Module    : {finding.module_id:<43} ║")
                print(f"║     Parameter : {finding.parameter:<43} ║")
                print(f"║     Severity  : {finding.impact:<43} ║")
                print(f"║     Confidence: {finding.confidence * 100:.0f}%{'':<39} ║")
                payload_display = finding.verify_payload if len(finding.verify_payload) <= 43 else finding.verify_payload[:40] + "..."
                print(f"║     Payload   : {payload_display:<43} ║")
                if i < total_val - 1:
                    print("╟" + "─" * width + "╢")
                    
        print("╚" + "═" * width + "╝")
