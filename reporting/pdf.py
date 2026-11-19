import os
import shutil
from datetime import datetime
from fpdf import FPDF
from core.context import TargetContext

class PDFReporter:
    def generate(self, context: TargetContext):
        safe_host = context.target.host.replace('.', '_') if context.target.host else "unknown"
        filename = f"reports/report_{safe_host}.pdf"
        os.makedirs("reports", exist_ok=True)

        pdf = FPDF()
        pdf.add_page()

        # 1. Header
        pdf.set_font("Arial", "B", 18)
        pdf.set_text_color(0, 100, 200)
        pdf.cell(0, 10, "TanPha V5 - Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")

        pdf.set_font("Arial", "I", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)

        # 2. Target Info
        pdf.set_font("Arial", "B", 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(30, 8, "Target URL:")
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 8, context.target.base_url, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Arial", "B", 11)
        pdf.cell(30, 8, "Host:")
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 8, context.target.host, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Arial", "B", 11)
        pdf.cell(30, 8, "Frameworks:")
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 8, f"{context.fingerprint.server} | {context.fingerprint.framework}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # 3. Vulnerability Summary
        total_vulns = len(context.results.validated)
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, f"Vulnerabilities Found: {total_vulns}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        # 4. Detail Table
        if total_vulns > 0:
            w_no = 8
            w_vuln = 35
            w_param = 25
            w_impact = 35
            w_payload = 87

            pdf.set_font("Arial", "B", 9)
            pdf.set_fill_color(200, 220, 255)

            # Header Tabel
            pdf.cell(w_no, 8, "#", border=1, fill=True, align="C")
            pdf.cell(w_vuln, 8, "Vulnerability", border=1, fill=True)
            pdf.cell(w_param, 8, "Parameter", border=1, fill=True)
            pdf.cell(w_impact, 8, "Impact", border=1, fill=True)
            pdf.cell(w_payload, 8, "Payload / Evidence", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Arial", "", 8)

            for i, finding in enumerate(context.results.validated, 1):
                vuln = str(finding.vulnerability)[:15]
                param = str(finding.parameter)[:10]
                impact = str(finding.impact)[:15]
                payload = str(finding.verify_payload or finding.assess_payload or "N/A")
                evidence = str(finding.evidence or "N/A")
                info_text = f"P: {payload[:30]} | E: {evidence[:40]}"

                pdf.cell(w_no, 8, str(i), border=1, align="C")
                pdf.cell(w_vuln, 8, vuln, border=1)
                pdf.cell(w_param, 8, param, border=1)
                pdf.cell(w_impact, 8, impact, border=1)
                pdf.cell(w_payload, 8, info_text, border=1, new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_font("Arial", "I", 10)
            pdf.set_text_color(0, 150, 0)
            pdf.cell(0, 10, "No validated vulnerabilities detected.", new_x="LMARGIN", new_y="NEXT")

        # 5. Save File
        pdf.output(filename)
        print(f"[+] PDF Report saved to: {filename}")

        # 6. Auto-copy ke Download (PAKAI PATH TERMUX YANG BENER)
        download_dir = os.path.expanduser("~/storage/downloads")
        
        if os.path.exists(download_dir):
            try:
                target_path = os.path.join(download_dir, os.path.basename(filename))
                shutil.copy(filename, target_path)
                print(f"[+] PDF Report ALSO saved to: {target_path}")
            except Exception as e:
                print(f"[!] Failed to copy to Download: {e}")
        else:
            print(f"[!] Termux Download folder not found. Run 'termux-setup-storage' first.")
