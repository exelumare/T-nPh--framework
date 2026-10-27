# 🚀 TànPhá Framework [Enterprise]
> Modular CLI Penetration Testing & Auto-Attack Framework for Android (Termux) & Linux.

**TànPhá** is a modular Python-based penetration testing framework designed for automated vulnerability assessment, stealthy exploitation, and post-exploitation operations directly from mobile or desktop environments.

---

## ⚙️ Enterprise Modules Available

1. **Advanced Arbitrary File Upload (Fully Automated)**
   * Automated field parameter detection, double extension bypass, and Magic Bytes Spoofing (GIF89a headers).
   * Real-time verification script to ensure the web shell is active and ready for execution.
2. **Command Injection Engine (Auto-Bypass & Enumeration)**
   * Tests multiple separator variations (semicolons, pipes, etc.) with automated URL Encoding to bypass WAFs.
   * Built-in post-exploitation enumeration engine (Kernel, Privileges, Network config).
3. **SQL Injection Scanner (Multi-DBMS & WAF Evasion)**
   * Detects error-based and union-based SQLi vulnerabilities using payload variations.
   * Autonomous Column Fuzzing engine to extract target table structures.
4. **PHP2Shell Core Engine (Stateful RAT)**
   * HTTP POST-based remote administration tool with regex output sanitization.
   * Supports persistent directory navigation (`cd`), instant system execution (`sysinfo`), and file upload/download capabilities.

---

## 📥 Installation & Usage

Ensure **Python 3** and the `requests` library are installed on your terminal (Termux / Linux):

```bash
# Clone the repository
git clone [https://github.com/USERNAME/tanpha-framework.git]
cd tanpha-framework

# Install dependencies
pip install requests

# Run the framework
python main.py

---

## ☕ Support & Donation

If you find this project useful and would like to support its development, feel free to buy me a coffee!

* **Saweria / Trakteer / Ko-fi:** `https://saweria.co/Exelumare'

Your support is greatly appreciated to keep this project updated! 🚀

