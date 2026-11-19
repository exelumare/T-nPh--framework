import os
import shutil
from datetime import datetime
from core.context import TargetContext

class HTMLReporter:
    def generate(self, context: TargetContext):
        safe_host = context.target.host.replace('.', '_') if context.target.host else "unknown"
        filename = f"reports/report_{safe_host}.html"
        os.makedirs("reports", exist_ok=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TanPha V5 - Scan Report</title>
            <style>
                body {{ font-family: 'Courier New', monospace; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 15px; }}
                .container {{ max-width: 1200px; margin: auto; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; }}
                h1, h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
                .summary {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }}
                .card {{ background: #21262d; padding: 15px; border-radius: 6px; flex: 1; min-width: 120px; text-align: center; border: 1px solid #30363d; }}
                .card h3 {{ margin: 0; font-size: 24px; color: #fff; }}
                .card p {{ margin: 5px 0 0 0; font-size: 12px; color: #8b949e; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
                th, td {{ border: 1px solid #30363d; padding: 10px; text-align: left; word-break: break-all; vertical-align: top; }}
                th {{ background-color: #21262d; color: #58a6ff; }}
                .payload {{ background: #0d1117; padding: 5px; border-radius: 4px; font-family: monospace; color: #7ee787; }}
                /* INI YANG KITA UBAH: Biar enter-nya kebaca */
                .evidence {{ background: #1f2428; padding: 8px; border-radius: 4px; color: #c9d1d9; font-size: 12px; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }}
                .tag {{ padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; display: inline-block; }}
                .tag.CRITICAL {{ background: #f85149; color: #fff; }}
                .tag.HIGH {{ background: #d29922; color: #fff; }}
                .tag.MEDIUM {{ background: #58a6ff; color: #fff; }}
                .tag.LOW {{ background: #2ea043; color: #fff; }}
                .tag.INFO {{ background: #8b949e; color: #fff; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🦅 TanPha V5 - Scan Report</h1>
                <p><strong>Target URL:</strong> {context.target.base_url}</p>
                <p><strong>Host:</strong> {context.target.host}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Summary</h2>
                <div class="summary">
                    <div class="card">
                        <h3>{len(context.results.validated)}</h3>
                        <p>Total Validated</p>
                    </div>
                    <div class="card">
                        <h3>{len(context.results.rejected)}</h3>
                        <p>Rejected</p>
                    </div>
                </div>

                <h2>Vulnerability Details</h2>
        """
        
        if not context.results.validated:
            html_content += "<p style='color:#2ea043; font-weight:bold;'>✅ No validated vulnerabilities detected on this target.</p>"
        else:
            html_content += """
                <table>
                    <tr>
                        <th style="width: 5%;">#</th>
                        <th style="width: 15%;">Vulnerability</th>
                        <th style="width: 10%;">Parameter</th>
                        <th style="width: 15%;">Impact</th>
                        <th style="width: 15%;">Payload</th>
                        <th style="width: 40%;">Evidence / Details</th>
                    </tr>
            """
            for i, finding in enumerate(context.results.validated, 1):
                impact_class = finding.impact if finding.impact in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "INFO"
                
                payload = str(finding.verify_payload or finding.assess_payload or "N/A")
                payload = payload.replace("<", "&lt;").replace(">", "&gt;")
                
                evidence = str(finding.evidence or "N/A")
                evidence = evidence.replace("<", "&lt;").replace(">", "&gt;")
                
                html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td><strong>{finding.vulnerability}</strong></td>
                        <td>{finding.parameter}</td>
                        <td><span class="tag {impact_class}">{finding.impact}</span></td>
                        <td><code class="payload">{payload}</code></td>
                        <td><div class="evidence">{evidence}</div></td>
                    </tr>
                """
            html_content += "</table>"

        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML Report saved to: {filename}")

        download_dirs = ["/sdcard/Download", os.path.expanduser("~/Downloads"), os.path.expanduser("~/storage/downloads")]
        for d_dir in download_dirs:
            if os.path.exists(d_dir) and os.path.isdir(d_dir):
                try:
                    shutil.copy(filename, os.path.join(d_dir, os.path.basename(filename)))
                    print(f"[+] HTML Report ALSO saved to: {d_dir}")
                    break
                except Exception:
                    pass
