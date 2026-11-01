import os
from datetime import datetime
from core.context import TargetContext


class HTMLReporter:
    def generate(self, context: TargetContext):
        # Ganti titik jadi underscore biar aman buat nama file
        safe_host = context.target.host.replace('.', '_') if context.target.host else "unknown"
        filename = f"reports/report_{safe_host}.html"
        os.makedirs("reports", exist_ok=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TanPha V4 - Scan Report</title>
            <style>
                body {{ font-family: 'Courier New', Courier, monospace; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 15px; }}
                .container {{ max-width: 1000px; margin: auto; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; }}
                h1, h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
                .summary {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }}
                .card {{ background: #21262d; padding: 15px; border-radius: 6px; flex: 1; min-width: 120px; text-align: center; border: 1px solid #30363d; }}
                .card h3 {{ margin: 0; font-size: 24px; color: #fff; }}
                .card p {{ margin: 5px 0 0 0; font-size: 12px; color: #8b949e; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
                th, td {{ border: 1px solid #30363d; padding: 10px; text-align: left; word-break: break-all; }}
                th {{ background-color: #21262d; color: #58a6ff; }}
                .payload {{ background: #0d1117; padding: 5px; border-radius: 4px; font-family: monospace; color: #7ee787; word-break: break-all; }}
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
                <h1>🦅 TanPha V4 - Scan Report</h1>
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
                        <th>#</th>
                        <th>Vulnerability</th>
                        <th>Parameter</th>
                        <th>Payload</th>
                        <th>Impact</th>
                        <th>Confidence</th>
                    </tr>
            """
            for i, finding in enumerate(context.results.validated, 1):
                impact_class = finding.impact if finding.impact in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "INFO"
                
                # Escape HTML tags biar payload <script> nggak ngerusak tampilan HTML laporan
                payload = str(finding.verify_payload or finding.assess_payload or "N/A")
                payload = payload.replace("<", "&lt;").replace(">", "&gt;")
                
                html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td><strong>{finding.vulnerability}</strong></td>
                        <td>{finding.parameter}</td>
                        <td><code class="payload">{payload}</code></td>
                        <td><span class="tag {impact_class}">{finding.impact}</span></td>
                        <td>{int(finding.confidence * 100)}%</td>
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
