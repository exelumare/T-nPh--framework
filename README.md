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

## 📥 Installation & Multi-Platform Usage

### 1. Android (Termux) & Linux (Ubuntu / Debian / Kali)
```bash
# Clone the repository
git clone [https://github.com/exelumare/T-nPh--framework.git]
cd tanpha-framework

# Install dependencies
pip install requests

# Run the framework
python main.py

### 2. Arch Linux / Manjaro (Virtual Environment)
'''bash
#clone the repository
git clone [https://github.com/exelumare/T-nPh--framework.git]
cd tanpha-framework

# Setup virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies & run
pip install requests
python main.py

### 3. Windows (CMD / PowerShell)
'''bash

git clone [https://github.com/exelumare/T-nPh--framework.git]
cd tanpha-framework

pip install requests
python main.py

#---☕ Support & Donation
​If you find this project useful and would like to support its ongoing development, feel free to contribute:
​Saweria: https://saweria.co/Exelumare
​Ko-fi / Buy Me a Coffee: https://ko-fi.com/exelumare

​⚠️ Disclaimer: This tool is created for educational purposes, cybersecurity research,
and authorized security testing only.
Misuse of this software is solely the user's responsibility.
