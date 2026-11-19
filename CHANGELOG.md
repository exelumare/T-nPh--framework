# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-10-31

### 🚀 Added (What's New)
*   **Auto Assessment Engine**: Introduced a state-machine architecture (`AutoAssessmentEngine`) for automated discovery, fingerprinting, and vulnerability assessment.
*   **LFI Module**: Added Local File Inclusion scanner with `php://filter` Base64 extraction and Multi-OS path traversal (Linux, Windows, Android).
*   **PHP2Shell (Stateful RAT)**: Added post-exploitation module with stateful directory tracking (`cd`), file upload/download, and system enumeration (`sysinfo`).
*   **Auto Login Engine**: Added `AuthManager` to automatically detect and bypass CSRF tokens for authenticated scanning.
*   **JSON Reporting**: Automated structured reports saved in the `reports/` directory.
*   **DVWA Auto-Configuration**: Added an optional feature to automatically set DVWA security levels during authenticated scans.

### 🔧 Changed
*   **Global Readiness**: Refactored 100% of the codebase, terminal outputs, and prompts to English.
*   **OOP Architecture**: Migrated from procedural scripts to Object-Oriented Programming (Classes, Dataclasses, Enums).
*   **HTTP Client V3**: Implemented a centralized HTTP client with Proxy support, delay/rate-limiting, and retry mechanisms.
*   **Dynamic Form Discovery**: Improved parameter discovery to handle complex POST forms and CSRF tokens.
*   **SQLi Engine**: Enhanced payload generation to support both String-based (Low) and Numeric-based (Medium) injections.

### 🐛 Fixed
*   Fixed `NameError` and `IndentationError` bugs from legacy scripts.
*   Fixed false positives in SQLi by implementing baseline structural fingerprinting.
*   Fixed output sanitization in Command Injection and File Upload using the "Marker Technique".
*   Fixed path extraction issues in the File Upload module for dynamic directory structures.

---

## [4.0.0] - Upcoming (What's Next)

### 🚧 Planned Features
*   **Advanced WAF Evasion**: Implementation of Level 2 (Chunked Encoding, Content-Type Confusion) and Level 3 (Origin IP Discovery) evasion techniques.
*   **New Modules**: XSS (Cross-Site Scripting), SSRF (Server-Side Request Forgery), and Subdomain Enumeration.
*   **Multi-Step/Stateful Scanning**: Support for complex vulnerabilities that require multi-step requests (e.g., DVWA High-level SQLi).
*   **CLI Arguments**: Full headless mode (`python main.py -u target.com -m sqli`) for CI/CD and automation integration.
*   **HTML/PDF Reporting**: Generate beautiful, client-ready reports directly from the framework.
