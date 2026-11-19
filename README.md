<p align="center">
  <img src="logo.png" alt="TànPhá Logo" width="200"/>
</p>

<h1 align="center">TànPhá V5 (Beta)</h1>

<p align="center">
  <i>An AI-Assisted Open-Source DAST Framework. Built from scratch on an Android Phone.</i>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#support">Support</a>
</p>

---

## 📖 About TànPhá

**TànPhá** (Vietnamese for *Destruction*) is a custom, lightweight Dynamic Application Security Testing (DAST) framework. It is designed to be fast, highly accurate, and accessible to everyone—from bug bounty hunters to security researchers.

Unlike enterprise tools that charge thousands of dollars, TànPhá is 100% free and open-source. 

> **Current Status:** Beta. 
> Our primary focus is on **Zero False Positives**. We believe a scanner should never waste a researcher's time with hallucinated alerts. 

### 🏆 Benchmark Results
In our testing against the **OWASP Benchmark** (Command Injection Category), TànPhá V5 achieved:
*   **Detection Rate (TPR):** 90%+
*   **False Positive Rate (FPR):** **0.0%**
*   *Note: We are continuously working to eliminate remaining False Negatives.*

## ✨ Key Features

*   **🧠 AI Hydra (Multi-Provider):** Uses a 4-tier AI fallback (OpenRouter, SambaNova, Mistral, Gemini) to verify vulnerabilities and eliminate false positives.
*   **🛡️ WAF Evasion:** Built-in `curl_cffi` integration to impersonate real Chrome browsers, bypassing Cloudflare/DataDome.
*   **🎯 Multi-Vector Injection:** Tests not just GET/POST parameters, but also HTTP Headers, Cookies, and Environment Variables.
*   **🖥️ Custom OS-Style UI:** A fully interactive, terminal-based OS-style interface (Neofetch style) with glitch boot sequences.
*   **📄 Automated Reporting:** Automatically generates professional JSON, HTML, and PDF reports.

## 🛠️ Installation

TànPhá is designed to run on Termux (Android) or any Linux environment.

```bash
# 1. Clone the repository
git clone https://github.com/exelumare/T-nPh--framework.git
cd T-nPh--framework

# 2. Install dependencies
pkg install python clang make openssl libffi libxml2 libxslt pkg-config -y
pip install -r requirements.txt

# 3. Setup Environment Variables
cp .env.example .env
nano .env # Add your API keys here
```

🚀 Usage

Run TànPhá in interactive menu mode:

```bash
python main.py
```

Run in headless mode (direct scan):

```bash
python main.py -u "https://target.com" -m full --delay 1.5
```

☕ Support the Project

TànPhá is built by a solo developer in his free time. It is completely free and will always be free.

However, if this tool helps you find a bug and earn a bounty, consider supporting the development! Your donations go directly to keeping the AI servers alive and buying coffee for late-night coding sessions.

· Ko-fi (International): https://ko-fi.com/exelumare

⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. Do not use TànPhá against systems you do not own or have explicit permission to test. The developer is not responsible for any misuse or damage caused by this tool.

---

Built with chaos, coffee, and pure Python. - Exelumare
