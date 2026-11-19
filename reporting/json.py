import json
import os
from dataclasses import asdict
from core.context import TargetContext

class JSONReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, context: TargetContext):
        report_data = {
            "target": asdict(context.target),
            "fingerprint": asdict(context.fingerprint),
            "baseline": asdict(context.baseline),
            "summary": {
                "total_validated": len(context.results.validated),
                "total_rejected": len(context.results.rejected),
                "total_inconclusive": len(context.results.inconclusive),
                "total_skipped": len(context.results.skipped),
                "evidence_pool_size": len(context.results.evidence_pool)
            },
            "findings": [asdict(f) for f in context.results.validated]
        }

        filename = f"report_{context.target.host.replace('.', '_')}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
            
        print(f"\n[+] JSON Report saved to: {filepath}")
