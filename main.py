import sys
import re
import json
import argparse
from functools import partial

# Network & Core Imports
from network.config import HTTPConfig, EvasionLevel
from network.client import HTTPClient
from core.context import TargetContext
from core.engine import AutoAssessmentEngine
from core.scope import ScopeManager
from core.auth import AuthManager
from core.sequence import SequenceStep

# Modules Imports
from modules.sqli import SQLInjectionModule
from modules.cmd_injection import CommandInjectionModule
from modules.upload import UploadModule
from modules.lfi import LFIModule
from modules.xss import XSSModule
from modules.ssrf import SSRFModule
from modules.subdomain import SubdomainModule
from modules.php2shell import run_php2shell_module
from modules.api_sqli import APISQLInjectionModule
from modules.api_fuzzer import APIFuzzerModule
from modules.sensitive_files import SensitiveFilesModule

# Utils Imports
from utils.platform import clear_screen
from utils.banner import print_banner, show_main_menu

INTERNAL_IDS = ["engine_init", "setup", "baseline", "discovery", "fingerprint", "sequence", "origin_ip", "external_api", "aggressive_evasion"]

def _build_modules(choice):
    """Maps the selected module string to the actual module classes."""
    m = {
        "full": [
            SQLInjectionModule(), CommandInjectionModule(), UploadModule(), 
            LFIModule(), XSSModule(), SSRFModule(), SubdomainModule(), 
            APIFuzzerModule(), APISQLInjectionModule()
        ],
        "sqli": [SQLInjectionModule()], 
        "cmd": [CommandInjectionModule()],
        "upload": [UploadModule()], 
        "lfi": [LFIModule()], 
        "xss": [XSSModule()],
        "ssrf": [SSRFModule()], 
        "subdomain": [SubdomainModule()], 
        "api": [APIFuzzerModule(), APISQLInjectionModule()], 
        "recon": [SensitiveFilesModule()]
    }
    return m.get(choice, [])

def _run_scan(args):
    """Core scanning function (Headless Mode)."""
    clear_screen()
    print_banner() 
    
    print("[*] Running in Headless Mode")
    print("⚠️  WARNING: Only use on systems you own or have WRITTEN permission to test.")
    print("⚠️  All activity is logged to ~/.tanpha_audit.log\n")

    evasion_map = {1: EvasionLevel.NONE, 2: EvasionLevel.STANDARD, 3: EvasionLevel.AGGRESSIVE}
    config = HTTPConfig(
        verify_tls=False, 
        evasion_level=evasion_map.get(args.evasion, EvasionLevel.NONE), 
        random_seed=42, 
        delay=args.delay
    )
    
    scope = ScopeManager()
    client = None

    try:
        selected_modules = _build_modules(args.module)
        module_ids = [mod.module_id for mod in selected_modules]
        allowed_mods = list(set(module_ids + INTERNAL_IDS))
        
        if args.module == "php2shell":
            allowed_mods.append("php2shell")
        
        try:
            scope.approve_session(args.url, duration_minutes=120, allowed_modules=allowed_mods)
            print(f"[*] Target Authorized: {args.url}")
        except Exception as e:
            print(f"[-] Authorize failed: {e}")
            return

        lab_checker = partial(scope.check, module_id="aggressive_evasion")
        client = HTTPClient(config, lab_checker=lab_checker)
        
        # OPSEC: Use alias instead of real identity
        client.session.headers.update({"X-Security-Researcher": "Exelumare"}) 
        auth_checker_setup = partial(scope.check, module_id="setup")

        if args.module == "php2shell":
            try:
                run_php2shell_module(client, auth_checker=partial(scope.check, module_id="php2shell"))
            finally:
                pass
            return

        if args.cookie:
            client.session.headers.update({"Cookie": args.cookie})
        elif args.login_url and args.user and args.passwd:
            auth = AuthManager(client, auth_checker=auth_checker_setup)
            if auth.auto_login(args.login_url, args.user, args.passwd, "username", "password", None):
                if args.sec_level and args.sec_level != "none":
                    base_url = args.login_url.rsplit('/', 1)[0] + "/"
                    _set_dvwa_security(client, base_url, args.sec_level, auth_checker_setup)

        sequence_steps = []
        if args.macro:
            try:
                with open(args.macro, "r") as f:
                    for sd in json.load(f).get("steps", []):
                        sequence_steps.append(SequenceStep(
                            name=sd.get("name", "Step"), method=sd.get("method", "GET"),
                            url=sd.get("url"), data=sd.get("data", {}), extract_vars=sd.get("extract_vars", {})
                        ))
            except Exception as e:
                print(f"[-] Macro load failed: {e}")
                return

        context = TargetContext()
        context.target.base_url = args.url
        context.http_client = client
        context.external_checker = partial(scope.check, module_id="external_api")

        print(f"[*] Target: {args.url} | Module: {args.module.upper()}")
        
        engine = AutoAssessmentEngine(context, selected_modules, sequence_steps=sequence_steps, scope_manager=scope)
        engine.run()
        
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")
    finally:
        if client:
            client.close()

def _set_dvwa_security(client, base_url, sec_level, auth_checker):
    """Helper to set DVWA security level automatically."""
    sec_url = base_url + "security.php"
    sec_get = client.request("GET", sec_url, auth_checker=auth_checker, bypass_mutation=True)
    if sec_get.success and sec_get.response:
        token_match = re.search(r'name=[\'"]user_token[\'"][^>]*value=[\'"]([^\'"]+)[\'"]', sec_get.response.text, re.IGNORECASE)
        sec_payload = {"security": sec_level, "seclev_submit": "Submit"}
        if token_match: 
            sec_payload["user_token"] = token_match.group(1)
        sec_res = client.request("POST", sec_url, data=sec_payload, auth_checker=auth_checker, bypass_mutation=True)
        if sec_res.success and sec_res.response:
            print(f"[+] DVWA Security set to: {sec_level.upper()}")

def main():
    parser = argparse.ArgumentParser(description="TànPhá V5")
    parser.add_argument("-u", "--url", help="Target URL (Headless mode)")
    parser.add_argument("-m", "--module", choices=["full","sqli","cmd","upload","lfi","xss","ssrf","subdomain","php2shell","api","recon"])
    parser.add_argument("-e", "--evasion", type=int, choices=[1,2,3], default=1)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("-c", "--cookie")
    parser.add_argument("--login-url")
    parser.add_argument("--user")
    parser.add_argument("--passwd")
    parser.add_argument("--sec-level", choices=["low","medium","high","none"], default="none")
    parser.add_argument("--macro")
    parser.add_argument("--weaponize", action="store_true", help="Enable Weaponized Exploit Layer")
    
    args = parser.parse_args()
    
    # Headless mode (Direct execution with -u)
    if args.url:
        if not args.module:
            args.module = "full"
            
        # Fix URL format if missing protocol
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "https://" + args.url
            
        _run_scan(args)
        
    # Interactive Menu Mode (Looping)
    else:
        while True:
            selected_module, target_url = show_main_menu()
            
            if target_url:
                # Fix URL format if missing protocol
                if not target_url.startswith("http://") and not target_url.startswith("https://"):
                    target_url = "https://" + target_url
                    
                args.url = target_url
                args.module = selected_module
                
                _run_scan(args)
                
                # Ask user if they want to return to menu
                print("\n" + "="*50)
                try:
                    choice = input("[?] Scan finished. Return to main menu? (y/n): ").strip().lower()
                    if choice != 'y':
                        print("[*] Exiting TànPhá. Goodbye!")
                        break
                except KeyboardInterrupt:
                    print("\n[*] Exiting TànPhá. Goodbye!")
                    break

if __name__ == "__main__":
    main()
