# 🚀 TànPhá Framework [Enterprise v2]
> Modular CLI Penetration Testing & Auto-Attack Framework for Android (Termux) & Linux.

**TànPhá** is a modular Python-based penetration testing framework designed for automated vulnerability assessment, stealthy exploitation, and post-exploitation operations directly from mobile or desktop environments.

---

## ⚙️ Enterprise Modules Available (v2 Architecture)

1. **Advanced Arbitrary File Upload (Fully Automated)**
   * Automated field parameter detection, double extension bypass, and Magic Bytes Spoofing (GIF89a headers).
   * Real-time verification script to ensure the web shell is active and ready for execution.
   * *(v2 Fix)* Header spoofing (`X-Forwarded-For`) now properly sent to bypass basic WAFs.

2. **Command Injection Engine (Auto-Bypass & Enumeration)**
   * Tests multiple separator variations (semicolons, pipes, etc.) with automated URL Encoding.
   * Built-in post-exploitation enumeration engine (Kernel, Privileges, Network config).
   * *(v2 Fix)* Resolved `NameError` crash on `urllib.parse.quote`.

3. **SQL Injection Scanner (Multi-DBMS & WAF Evasion)**
   * Detects error-based and union-based SQLi vulnerabilities using payload variations.
   * Autonomous Column Fuzzing engine to extract target table structures.
   * *(v2 Update)* **Layer 1 Engine**: Structural Fingerprinting (anti-CSRF false positive), Median+MAD timing, and Request-Budget Guard (skip enumeration if UNION fails).

4. **PHP2Shell Core Engine (Stateful RAT)**
   * HTTP POST-based remote administration tool with regex output sanitization.
   * Supports persistent directory navigation (`cd`), instant system execution (`sysinfo`), and file upload/download capabilities.

---

## 🛡️ v2 Foundation Features (New)
* **Centralized Audit Log**: Every exploit action is logged to `logs/audit_YYYYMMDD.jsonl` for legal defensibility.
* **Scope Manager**: Define your authorized targets in `scope.json` to skip the interactive authorization prompt.
* **Anti-Crash Architecture**: A failing module will not terminate the framework; it safely returns to the main menu.
* **Cross-Platform**: Works seamlessly on Termux (Android), Linux, macOS, and Windows.

---

## 📥 Installation & Multi-Platform Usage

### 1. Android (Termux) & Linux (Ubuntu / Debian / Kali)
```bash
# Clone the repository
git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework

# Install dependencies
pip install requests

# Run the framework
python main.py

## 2. Arch linux/Manjaro (virtual environment)

# Clone the repository
git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework

# Setup virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies & run
pip install requests
python main.py

## 3. Windows (CMD/Power Shell)

git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework

pip install requests
python main.py


---

📁 Repository Structure

```text
T-nPh--framework/
├── main.py                 # Entry point (v2)
├── modules/                # Exploit modules (upload, cmd_injection, sqli, php2shell)
├── utils/                  # Core helpers (audit, scope, platform)
├── logs/                   # Auto-generated audit logs
├── requirements.txt        # Dependencies
└── README.md
```

---

#---☕ Support & Donation
If you find this project useful and would like to support its ongoing development, feel free to contribute:

· Saweria: https://saweria.co/Exelumare
· Ko-fi / Buy Me a Coffee: https://ko-fi.com/exelumare

⚠️ Disclaimer: This tool is created for educational purposes, cybersecurity research, and authorized security testing only. Misuse of this software is solely the user's responsibility.

```
