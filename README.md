<div align="center">
  <img src="logo.png" alt="TanPha Logo" width="250"/>
  <h1>TànPhá Framework [v3 Enterprise]</h1>
  <p><b>Modular CLI Penetration Testing & Auto-Attack Framework for Termux & Linux.</b></p>
  <p>
    <img src="https://img.shields.io/badge/Version-3.0.0-blue" alt="Version">
    <img src="https://img.shields.io/badge/Python-3.8%2B-green" alt="Python">
    <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-orange" alt="Platform">
  </p>
</div>

**TànPhá** is a modular, automated penetration testing framework designed for cybersecurity researchers, bug hunters, and red teamers. Built with a focus on efficiency, it allows you to perform discovery, vulnerability assessment, and post-exploitation directly from your mobile device (Termux) or desktop (Linux).

## 🚀 What New in Features (V3 Architecture)

*   **Auto Assessment Engine**: A state-machine based engine that automates Discovery, Fingerprinting, Assessment, Validation, and Reporting.
*   **Multi-Vector Exploitation**:
    *   **SQL Injection**: Error-based, Boolean-based, and Time-based blind. Supports both GET and POST methods with CSRF bypass.
    *   **Command Injection**: Direct output and Time-based blind. Includes an Interactive Pseudo-Shell.
    *   **File Upload**: Polyglot magic bytes bypass, dynamic path extraction, and interactive web shell.
    *   **LFI (Local File Inclusion)**: Path traversal and `php://filter` wrapper extraction (Multi-OS support).
*   **PHP2Shell (Stateful RAT)**: A post-exploitation module with stateful directory tracking (`cd`), file upload/download, and system enumeration.
*   **Auto Login Engine**: Automatically detects and bypasses CSRF tokens to scan authenticated pages.
*   **WAF Evasion**: Request mutation and payload obfuscation techniques.
*   **Automated Reporting**: Generates clean JSON reports for every scan.

## 🗺️ Roadmap (What's Next in V4)

We are constantly improving TànPhá. Here is a sneak peek at what's coming in the next major update:

*   **Advanced WAF Evasion**: Level 2 (Chunked Encoding, Content-Type Confusion) & Level 3 (Origin IP Discovery) techniques.
*   **New Exploit Modules**: XSS (Cross-Site Scripting), SSRF (Server-Side Request Forgery), and Subdomain Enumeration.
*   **Multi-Step/Stateful Scanning**: Support for complex vulnerabilities that require multi-step requests (e.g., DVWA High-level SQLi).
*   **CLI Arguments (Headless Mode)**: `python main.py -u target.com -m sqli` for CI/CD automation integration.
*   **HTML/PDF Reporting**: Generate beautiful, client-ready reports directly from the framework.

## 📥 Installation

### For Termux (Android)
```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework
pip install -r requirements.txt

### For Linux (Ubuntu / Debian / Kali)

```bash
sudo apt update && sudo apt install python3 python3-pip git
git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework
pip3 install -r requirements.txt
```

🛠️ Usage

Run the framework:

```bash
python main.py
```

Workflow Example:

1. Select a scan mode (e.g., Full Auto Scan or SQL Injection Only).
2. Enter your target URL (e.g., http://target.com/vulnerabilities/sqli/).
3. Choose your WAF Evasion level (1-3).
4. Choose Authentication Method (Manual Cookie or Auto Login).
5. The engine will automatically scan, validate, and report the findings.

📸 Screenshots

(You can add terminal screenshots here later)

⚠️ Disclaimer

This tool is created for educational purposes, cybersecurity research, and authorized security testing only. Do not use this tool against targets without explicit written permission. The author is not responsible for any misuse or illegal activities. Use it at your own risk.

☕ Support & Donation

If you find this project useful and would like to support its ongoing development:

· Saweria: https://saweria.co/Exelumare
· Ko-fi: https://ko-fi.com/exelumare

---

Built with ❤️ for the global cybersecurity community.

```
