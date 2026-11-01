<p align="center">
  <img src="https://raw.githubusercontent.com/exelumare/T-nPh--framework/master/assets/logo.png" alt="TanPha Logo" width="300">
</p>

<h1 align="center">TànPhá Framework V4</h1>
<h3 align="center">The Global Foundation Edition</h3>

<p align="center">
  <a href="https://saweria.co/Exelumare"><img src="https://img.shields.io/badge/Saweria-Donate-orange?style=for-the-badge&logo=buymeacoffee" alt="Saweria"></a>
  <a href="https://ko-fi.com/exelumare"><img src="https://img.shields.io/badge/Ko--fi-Support-blue?style=for-the-badge&logo=ko-fi" alt="Ko-fi"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-4.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8%2B-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Global%20Ready-red.svg" alt="Status">
</p>

---

## 📖 Overview
**TànPhá** is a modular, enterprise-grade Command-Line Interface (CLI) Penetration Testing Framework. Designed for beginner bug hunters with limited devices (Android/Termux) but capable of scanning global web applications. 

V4 is a massive architectural leap from V3, introducing **Multi-Step Sequence Engines**, **Headless CLI Mode**, and **Advanced WAF Evasion**.

---

## 🚀 What's New in V4 (The Birthday Edition)
V4 is not just an update; it's a total overhaul. Here is what we brought to the table:

1. **Stateful Sequence Engine (`core/sequence.py`)**
   - Say goodbye to hardcoded logic. V4 can process JSON macros (`--macro`) to handle complex, multi-step web apps (e.g., bypassing CSRF, establishing sessions, then injecting payloads).

2. **True Headless Mode**
   - Run fully automated scans without interactive prompts.
   - Example: `python main.py -u http://target.com -m xss -e 3`

3. **WAF Evasion Level 2 (`network/mutation.py`)**
   - Implemented **Chunked Transfer Encoding** and **Content-Type Confusion** to bypass modern Web Application Firewalls (WAF).

4. **New Global Modules:**
   - **XSS Module:** Detects Reflected & Stored XSS with context-aware payloads (Tested on Google XSS Game).
   - **SSRF Module:** Smart Request engine (GET/POST) with Time-Based (Blind) SSRF detection and Universal Indicators.
   - **Subdomain Enumeration:** Automated recon using `crt.sh` API to find hidden subdomains.

5. **Upgraded Legacy Modules (V3 -> V4):**
   - **LFI:** Added `file://` Stream Wrapper bypass to defeat `fnmatch` restrictions (DVWA High). Includes Auto Base64 Decoder for `php://filter`.
   - **CMD Injection:** Fixed Pseudo-Shell output using Newline (`\n`) separators for synchronous execution.
   - **SQLi:** Upgraded to a Hybrid Engine (String & Numeric). Handles CSRF tokens and detects HTTP status code changes.
   - **File Upload & PHP2Shell:** Preserved and stabilized.

6. **HTML Reporting (`reporting/html.py`)**
   - Generates a beautiful, responsive Dark-Mode HTML report automatically. No more reading raw JSON.

---

## 🗺️ Roadmap (What's Next in V4)

We are constantly improving TànPhá. Here is a sneak peek at what's coming in the next major update:

*   **Advanced WAF Evasion**: Level 2 (Chunked Encoding, Content-Type Confusion) & Level 3 (Origin IP Discovery) techniques.
*   **New Exploit Modules**: XSS (Cross-Site Scripting), SSRF (Server-Side Request Forgery), and Subdomain Enumeration.
*   **Multi-Step/Stateful Scanning**: Support for complex vulnerabilities that require multi-step requests (e.g., DVWA High-level SQLi).
*   **CLI Arguments (Headless Mode)**: `python main.py -u target.com -m sqli` for CI/CD automation integration.
*   **HTML/PDF Reporting**: Generate beautiful, client-ready reports directly from the framework.

## 📥 Installation

```bash
# 1. Update system and install dependencies
pkg update && pkg upgrade -y
pkg install python git -y

# 2. Clone the repository
git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework

# 3. Install Python requirements
pip install -r requirements.txt

# 4. Run the framework
python main.py

---

💻 Usage

1. Interactive Mode (Beginner Friendly)

Simply run the tool and follow the on-screen menus.

```bash
python main.py
```

2. Headless Mode (Automation & Scripting)

Run scans directly from your terminal without prompts.

```bash
python main.py -u <TARGET_URL> -m <MODULE> -e <EVASION_LEVEL>
```

Arguments:

· -u, --url: Target URL.
· -m, --module: full, sqli, cmd, upload, lfi, xss, ssrf, subdomain, php2shell.
· -e, --evasion: 1 (None), 2 (Standard), 3 (Aggressive/Chunked).
· -c, --cookie: Manual authentication via Cookie string.
· --login-url, --user, --passwd: Auto-login credentials.
· --macro: Path to a JSON file for Multi-Step sequences.

Examples:

```bash
# Scan XSS on a global target
python main.py -u "https://xss-game.appspot.com/level1/frame?query=test" -m xss -e 1

# Scan SQLi with Auto-Login on DVWA High
python main.py -u "http://127.0.0.1:8080/vulnerabilities/sqli/" -m sqli -e 3 --login-url "http://127.0.0.1:8080/login.php" --user admin --passwd password --sec-level high
```

3. Multi-Step Macro (Advanced)

For complex web apps (like DVWA High SQLi), use a Macro JSON file.

```bash
python main.py -u "http://target.com/vuln.php" -m sqli --macro dvwa_sqli_high.json
```

---

🧩 Available Modules

Module Description Global Ready
XSS Reflected, Stored, DOM-context breakout ✅
SQLi Error, Boolean, Time-Based (Hybrid) ✅
SSRF Internal fetch, Cloud Metadata, Blind ✅
LFI Path Traversal, Stream Wrapper, Log Poisoning ✅
CMD Direct, Time-Based, Interactive Shell ✅
Subdomain crt.sh Reconnaissance ✅

---

## 🔮 Roadmap to V5 (The Birthday Edition)
V4 is just the foundation. Here is the blueprint for the upcoming V5 (Target: November 20th):
- [ ] **Out-of-Band (OOB) Engine:** Interactsh integration for Blind SSRF/SQLi.
- [ ] **API & JSON Fuzzing:** Support for REST APIs and JWT injection.
- [ ] **WAF Evasion L3:** Origin IP Discovery (Bypassing Cloudflare).
- [ ] **DOM XSS Scanner:** Headless browser integration.
- [ ] **SQLi Heuristic & ML:** Reducing False Negatives with lightweight Machine Learning.
- [ ] **LFI/RCE Expansion:** Log Poisoning & advanced wrappers.
- [ ] **LFI Wordlist Fuzzing:** Automated `.env` and config file hunting.
- [ ] **PDF Reporting:** Professional client-ready reports.
- [ ] **Full High-Level Bypasses:** Advanced payloads for all modules.

---

---

## ☕ Support the Developer
If TànPhá helps you find bugs, secure your applications, or land a bug bounty, consider buying me a coffee! Your support keeps this project alive and fuels the development of V5.

<div align="center">
  <a href="https://saweria.co/Exelumare" target="_blank">
    <img src="https://img.shields.io/badge/Saweria-Indonesia-orange?style=for-the-badge" alt="Saweria">
  </a>
  <a href="https://ko-fi.com/exelumare" target="_blank">
    <img src="https://img.shields.io/badge/Ko--fi-Global-blue?style=for-the-badge&logo=ko-fi" alt="Ko-fi">
  </a>
</div>

---

⚠️ Disclaimer

TànPhá is intended for educational purposes and authorized penetration testing only. Do not use this tool on websites you do not own or have permission to test. The developer is not responsible for any illegal activities or damage caused by this tool.

---

<p align="center">Made with ❤️ and ☕ on Termux</p>
```

---
