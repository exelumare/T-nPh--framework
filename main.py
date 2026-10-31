import sys
import re
from network.config import HTTPConfig, EvasionLevel
from network.client import HTTPClient
from core.context import TargetContext
from core.engine import AutoAssessmentEngine
from core.auth import AuthManager
from modules.sqli import SQLInjectionModule
from modules.cmd_injection import CommandInjectionModule
from modules.upload import UploadModule
from modules.lfi import LFIModule
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
    print("  0. Exit")
    
    print("\n[ WAF Evasion Level ]")
    print("  1. None (Lab/CTF)")
    print("  2. Standard")
    print("  3. Aggressive")

def main():
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
            elif sec_level != "none":
                print(f"[-] Level '{sec_level}' is not valid. Skipping.")
        else:
            print("[-] Auto Login failed. Falling back to Manual Cookie.")
            cookie_input = _safe_input("[?] Enter Cookie manually (optional): ").strip()
            if cookie_input:
                client.session.headers.update({"Cookie": cookie_input})

    context = TargetContext()
    context.target.base_url = target_url
    context.http_client = client

    selected_modules = []
    if choice == "1":
        selected_modules = [SQLInjectionModule(), CommandInjectionModule(), UploadModule(), LFIModule()]
    elif choice == "2":
        selected_modules = [SQLInjectionModule()]
    elif choice == "3":
        selected_modules = [CommandInjectionModule()]
    elif choice == "4":
        selected_modules = [UploadModule()]
    elif choice == "5":
        selected_modules = [LFIModule()]

    engine = AutoAssessmentEngine(context, selected_modules)
    
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted.")
    finally:
        client.close()

if __name__ == "__main__":
    main()
