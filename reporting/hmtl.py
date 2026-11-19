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
                body {{ font-family: 'Courier New', monospace; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 10px; }}
                .container {{ max-width: 1000px; margin: auto; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; }}
                h1, h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
                .summary {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
                .card {{ background: #21262d; padding: 10px; border-radius: 6px; flex: 1; min-width: 100px; text-align: center; border: 1px solid #30363d; }}
                .card h3 {{ margin: 0; font-size: 20px; color: #fff; }}
                .card p {{ margin: 5px 0 0 0; font-size: 11px; color: #8b949e; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }}
                th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; word-break: break-word; vertical-align: top; }}
                th {{ background-color: #21262d; color: #58a6ff; }}
                .payload {{ background: #0d1117; padding: 4px; border-radius: 4px; font-family: monospace; color: #7ee787; word-break: break-all; }}
                .evidence {{ background: #1f2428; padding: 8px; border-radius: 4px; color: #c9d1d9; font-size: 11px; white-space: pre-wrap; font-family: monospace; }}
                .tag {{ padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; display: inline-block; }}
                .tag.CRITICAL {{ background: #f85149; color: #fff; }}
                .tag.HIGH {{ background: #d29922; color: #fff; }}
                .tag.MEDIUM {{ background: #58a6ff; color: #fff; }}
                .tag.LOW {{ background: #2ea043; color: #fff; }}
                .tag.INFO {{ background: #8b949e; color: #fff; }}
                /* RESPONSIVE MOBILE */
                @media screen and (max-width: 600px) {{
                    table, thead, tbody, th, td, tr {{ display: block; width: 100%; }}
                    thead tr {{ position: absolute; top: -9999px; left: -9999px; }}
                    tr {{ border: 1px solid #30363d; margin-bottom: 10px; padding: 5px; border-radius: 6px; }}
                    td {{ border: none; border-bottom: 1px solid #30363d; position: relative; padding-left: 40%; padding-bottom: 5px; }}
                    td:before {{ position: absolute; top: 5px; left: 5px; width: 35%; padding-right: 10px; white-space: nowrap; font-weight: bold; color: #58a6ff; }}
                    td:nth-of-type(1):before {{ content: "#"; }}
                    td:nth-of-type(2):before {{ content: "Vulnerability"; }}
                    td:nth-of-type(3):before {{ content: "Parameter"; }}
                    td:nth-of-type(4):before {{ content: "Impact"; }}
                    td:nth-of-type(5):before {{ content: "Payload"; }}
                    td:nth-of-type(6):before {{ content: "Evidence"; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🦅 TanPha V5</h1>
                <p><strong>Target:</strong> {context.target.base_url}</p>
                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Summary</h2>
                <div class="summary">
                    <div class="card">
                        <h3>{len(context.results.validated)}</h3>
                        <p>Validated</p>
                    </div>
                    <div class="card">
                        <h3>{len(context.results.rejected)}</h3>
                        <p>Rejected</p>
                    </div>
                </div>

                <h2>Findings</h2>
        """
        
        if not context.results.validated:
            html_content += "<p style='color:#2ea043; font-weight:bold;'>✅ No validated vulnerabilities.</p>"
        else:
            html_content += """
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Vulnerability</th>
                            <th>Parameter</th>
                            <th>Impact</th>
                            <th>Payload</th>
                            <th>Evidence / Details</th>
                        </tr>
                    </thead>
                    <tbody>
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
                            <td><div class="payload">{payload}</div></td>
                            <td><div class="evidence">{evidence}</div></td>
                        </tr>
                """
            html_content += "</tbody></table>"

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
