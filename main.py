import sys
import re
import json
import argparse
from network.config import HTTPConfig, EvasionLevel
from network.client import HTTPClient
from core.context import TargetContext
from core.engine import AutoAssessmentEngine
from core.auth import AuthManager
from core.sequence import SequenceStep
from modules.sqli import SQLInjectionModule
from modules.cmd_injection import CommandInjectionModule
from modules.upload import UploadModule
from modules.lfi import LFIModule
from modules.xss import XSSModule
from modules.ssrf import SSRFModule
from modules.subdomain import SubdomainModule
from modules.php2shell import run_php2shell_module
from utils.platform import clear_screen
from utils.banner import print_banner


def _safe_input(prompt: str) -> str:
    if not sys.stdin.isatty():
        print(f"{prompt} <Non-TTY environment, aborting.>")
        sys.exit(1)
    return input(prompt)


def show_menu():
    print("\n[ Scan Mode Selection ]")
    print("  1. Full Auto Scan (All Modules)")
    print("  2. SQL Injection Only")
    print("  3. Command Injection Only")
    print("  4. File Upload Only")
    print("  5. LFI Only")
    print("  6. PHP2Shell Manager (Connect to existing shell)")
    print("  7. XSS Only")
    print("  8. SSRF Only")
    print("  9. Subdomain Enumeration (Recon)")
    print("  0. Exit")
    
    print("\n[ WAF Evasion Level ]")
    print("  1. None (Lab/CTF)")
    print("  2. Standard")
    print("  3. Aggressive (Chunked & Advanced)")


def _set_dvwa_security(client, base_url, sec_level):
    """Helper to set DVWA security level (used in both interactive & headless)."""
    sec_url = base_url + "security.php"
    sec_get = client.request("GET", sec_url, bypass_mutation=True)
    
    if sec_get.success and sec_get.response:
        token_match = re.search(r'name=[\'"]user_token[\'"][^>]*value=[\'"]([^\'"]+)[\'"]', sec_get.response.text, re.IGNORECASE)
        
        sec_payload = {"security": sec_level, "seclev_submit": "Submit"}
        if token_match:
            sec_payload["user_token"] = token_match.group(1)
            print(f"[+] Security Token found: {token_match.group(1)[:10]}...")
        
        sec_res = client.request("POST", sec_url, data=sec_payload, bypass_mutation=True)
        
        if sec_res.success and sec_res.response:
            if sec_res.response.status_code in (301, 302):
                print(f"[+] DVWA Security Level set to: {sec_level.upper()}")
            elif f"Security level is now set to: {sec_level}" in sec_res.response.text:
                print(f"[+] DVWA Security Level set to: {sec_level.upper()}")
            else:
                print("[-] Failed to set security level.")
    else:
        print("[-] Failed to access security.php (might not be DVWA).")


def run_headless(args):
    clear_screen()
    print_banner()
    print("[*] Running in Headless Mode")
    
    # 1. Setup Config & Client
    evasion_map = {1: EvasionLevel.NONE, 2: EvasionLevel.STANDARD, 3: EvasionLevel.AGGRESSIVE}
    selected_evasion = evasion_map.get(args.evasion, EvasionLevel.NONE)
    
    config = HTTPConfig(verify_tls=False, evasion_level=selected_evasion, random_seed=42) 
    client = HTTPClient(config)

    # 2. Special case for PHP2Shell
    if args.module == "php2shell":
        try:
            run_php2shell_module(client)
        finally:
            client.close()
        return

    # 3. Authentication Logic
    if args.cookie:
        client.session.headers.update({"Cookie": args.cookie})
        print("[*] Authentication: Manual Cookie")
    elif args.login_url and args.user and args.passwd:
        print(f"[*] Attempting Auto Login to: {args.login_url}")
        auth = AuthManager(client)
        success = auth.auto_login(args.login_url, args.user, args.passwd, "username", "password", None)
        
        if success:
            print("[+] LOGIN SUCCESS! Session cookie established.")
            if args.sec_level and args.sec_level != "none":
                base_url = args.login_url.rsplit('/', 1)[0] + "/"
                _set_dvwa_security(client, base_url, args.sec_level)
        else:
            print("[-] Auto Login failed. Continuing without auth.")
    else:
        print("[*] No authentication provided, running anonymously.")

    # 4. Load Multi-Step Macro (V4 ADDED)
    sequence_steps = []
    if args.macro:
        print(f"[*] Loading Multi-Step Macro from: {args.macro}")
        try:
            with open(args.macro, "r") as f:
                macro_data = json.load(f)
                for step_data in macro_data.get("steps", []):
                    step = SequenceStep(
                        name=step_data.get("name", "Unnamed Step"),
                        method=step_data.get("method", "GET"),
                        url=step_data.get("url"),
                        data=step_data.get("data", {}),
                        extract_vars=step_data.get("extract_vars", {})
                    )
                    sequence_steps.append(step)
                print(f"[+] Loaded {len(sequence_steps)} sequence steps.")
        except Exception as e:
            print(f"[-] Failed to load macro: {e}")
            sys.exit(1)

    # 5. Setup Context & Modules
    context = TargetContext()
    context.target.base_url = args.url
    context.http_client = client

    selected_modules = []
    if args.module == "full":
        selected_modules = [
            SQLInjectionModule(), CommandInjectionModule(), UploadModule(), 
            LFIModule(), XSSModule(), SSRFModule(), SubdomainModule()
        ]
    elif args.module == "sqli":
        selected_modules = [SQLInjectionModule()]
    elif args.module == "cmd":
        selected_modules = [CommandInjectionModule()]
    elif args.module == "upload":
        selected_modules = [UploadModule()]
    elif args.module == "lfi":
        selected_modules = [LFIModule()]
    elif args.module == "xss":
        selected_modules = [XSSModule()]
    elif args.module == "ssrf":
        selected_modules = [SSRFModule()]
    elif args.module == "subdomain":
        selected_modules = [SubdomainModule()]

    print(f"[*] Target: {args.url}")
    print(f"[*] Module: {args.module.upper()} | Evasion Level: {args.evasion}")

    # 6. Run Engine (Pass sequence_steps)
    engine = AutoAssessmentEngine(context, selected_modules, sequence_steps=sequence_steps)
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted.")
    finally:
        client.close()


def run_interactive():
    """V3 Interactive Logic (Preserved)"""
    clear_screen()
    print_banner()
    
    show_menu()
    choice = _safe_input("\n[?] Choose scan mode: ").strip()
    if choice == "0": sys.exit(0)

    # PHP2Shell Manager (Bypass scan mode)
    if choice == "6":
        config = HTTPConfig(verify_tls=False, evasion_level=EvasionLevel.NONE, random_seed=42)
        client = HTTPClient(config)
        try:
            run_php2shell_module(client)
        finally:
            client.close()
        return

    target_url = _safe_input("[?] Enter target URL: ").strip()
    if not target_url: sys.exit(1)
    
    evasion_choice = _safe_input("[?] Choose evasion level (1-3, default 2): ").strip() or "2"
    
    evasion_map = {"1": EvasionLevel.NONE, "2": EvasionLevel.STANDARD, "3": EvasionLevel.AGGRESSIVE}
    selected_evasion = evasion_map.get(evasion_choice, EvasionLevel.STANDARD)

    config = HTTPConfig(verify_tls=False, evasion_level=selected_evasion, random_seed=42) 
    client = HTTPClient(config)

    print("\n[ Authentication Method ]")
    print("  1. Manual Cookie (Paste PHPSESSID)")
    print("  2. Auto Login (Experimental)")
    auth_choice = _safe_input("[?] Choose method (default 1): ").strip() or "1"

    if auth_choice == "1":
        cookie_input = _safe_input("[?] Enter Cookie (optional, press Enter if none): ").strip()
        if cookie_input:
            client.session.headers.update({"Cookie": cookie_input})
            
    elif auth_choice == "2":
        login_url = _safe_input("[?] Login URL (e.g., http://target.com/login.php): ").strip()
        user_field = _safe_input("[?] Username Field (default: username): ").strip() or "username"
        pass_field = _safe_input("[?] Password Field (default: password): ").strip() or "password"
        csrf_field = _safe_input("[?] CSRF Field (default: auto-detect, type 'none' to skip): ").strip()
        if csrf_field.lower() == 'none': csrf_field = None
        
        username = _safe_input("[?] Username: ").strip()
        password = _safe_input("[?] Password: ").strip()
        
        auth = AuthManager(client)
        success = auth.auto_login(login_url, username, password, user_field, pass_field, csrf_field)
        
        if success:
            print("\n[?] Set DVWA Security Level?")
            print("    Options: none / low / medium / high")
            print("    (Type 'none' or press Enter for global websites)")
            sec_level = _safe_input("    Level (default: none): ").strip().lower() or "none"
            
            if sec_level in ["low", "medium", "high"]:
                base_url = login_url.rsplit('/', 1)[0] + "/"
                _set_dvwa_security(client, base_url, sec_level)
            elif sec_level != "none":
                print(f"[-] Level '{sec_level}' is not valid. Skipping.")
        else:
            print("[-] Auto Login failed. Falling back to Manual Cookie.")
            cookie_input = _safe_input("[?] Enter Cookie manually (optional): ").strip()
            if cookie_input:
                client.session.headers.update({"Cookie": cookie_input})

    # Ask for Macro in interactive mode (Optional)
    macro_path = _safe_input("[?] Path to Multi-Step Macro JSON (optional, press Enter to skip): ").strip()
    sequence_steps = []
    if macro_path:
        try:
            with open(macro_path, "r") as f:
                macro_data = json.load(f)
                for step_data in macro_data.get("steps", []):
                    sequence_steps.append(SequenceStep(
                        name=step_data.get("name", "Unnamed Step"),
                        method=step_data.get("method", "GET"),
                        url=step_data.get("url"),
                        data=step_data.get("data", {}),
                        extract_vars=step_data.get("extract_vars", {})
                    ))
            print(f"[+] Loaded {len(sequence_steps)} sequence steps.")
        except Exception as e:
            print(f"[-] Failed to load macro: {e}")

    context = TargetContext()
    context.target.base_url = target_url
    context.http_client = client

    selected_modules = []
    if choice == "1":
        selected_modules = [
            SQLInjectionModule(), CommandInjectionModule(), UploadModule(), 
            LFIModule(), XSSModule(), SSRFModule(), SubdomainModule()
        ]
    elif choice == "2":
        selected_modules = [SQLInjectionModule()]
    elif choice == "3":
        selected_modules = [CommandInjectionModule()]
    elif choice == "4":
        selected_modules = [UploadModule()]
    elif choice == "5":
        selected_modules = [LFIModule()]
    elif choice == "7":
        selected_modules = [XSSModule()]
    elif choice == "8":
        selected_modules = [SSRFModule()]
    elif choice == "9":
        selected_modules = [SubdomainModule()]

    engine = AutoAssessmentEngine(context, selected_modules, sequence_steps=sequence_steps)
    
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted.")
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="TanPha V4 - Headless & Interactive Mode")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-m", "--module", choices=["full", "sqli", "cmd", "upload", "lfi", "xss", "ssrf", "subdomain", "php2shell"], default="full", help="Module to run (default: full)")
    parser.add_argument("-e", "--evasion", type=int, choices=[1, 2, 3], default=1, help="Evasion level (1: None, 2: Standard, 3: Aggressive)")
    
    # Auth Arguments
    parser.add_argument("-c", "--cookie", help="Manual Cookie (e.g., 'PHPSESSID=abc123')")
    parser.add_argument("--login-url", help="Auto Login URL (e.g., 'http://target.com/login.php')")
    parser.add_argument("--user", help="Username for auto login")
    parser.add_argument("--passwd", help="Password for auto login")
    parser.add_argument("--sec-level", choices=["low", "medium", "high", "none"], default="none", help="Set DVWA Security Level")
    
    # V4 Multi-Step Argument
    parser.add_argument("--macro", help="Path to JSON file for Multi-Step Sequence")
    
    args = parser.parse_args()

    # If -u (url) is provided, run Headless. Otherwise, run Interactive V3.
    if args.url:
        run_headless(args)
    else:
        run_interactive()

if __name__ == "__main__":
    main()
