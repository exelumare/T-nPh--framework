"""
TànPhá Framework v2 — Final Entry Point.
Semua modul sudah dipindahkan ke folder `modules/` (100% v2).
"""
import sys

from utils import clear_screen, safe_input, describe_env
from utils import AuditLog, ScopeManager, get_operator

# --- Import semua modul v2 ---
from modules.upload import run_upload_module
from modules.cmd_injection import run_cmd_injection_module
from modules.sqli import run_sqli_module
from modules.php2shell import run_php2shell_module

def banner_v2():
    print("=" * 60)
    print("      T à n P h á   F r a m e w o r k  [v2 Final]")
    print("      Modular CLI Penetration Testing & Auto-Attack")
    print("=" * 60)
    print(f"  env   : {describe_env()}")
    print(f"  audit : logs/audit_YYYYMMDD.jsonl")

def show_menu():
    print("\n[ Menu Utama - Modul Enterprise (100% v2) ]")
    print("  1. Advanced Arbitrary File Upload (Fully Automated)")
    print("  2. Command Injection Engine (Auto-Bypass & Enumeration)")
    print("  3. SQL Injection Scanner")
    print("  4. PHP2Shell Core Engine")
    print("  0. Keluar")

def main_menu_v2():
    # Cek dependencies
    try:
        import requests
    except ImportError:
        print("[-] Modul 'requests' belum di-install. Jalankan: pip install requests")
        sys.exit(1)

    clear_screen()
    banner_v2()

    operator = get_operator()
    scope = ScopeManager("scope.json")
    audit = AuditLog(operator=operator)

    print(f"[+] Operator : {operator}")
    print(f"[+] {scope.summary()}")
    print(f"[+] Audit log: {audit.path}")
    print()
    input("Tekan Enter untuk masuk menu...")

    modules = {
        "1": ("upload",        run_upload_module),
        "2": ("cmd_injection", run_cmd_injection_module),
        "3": ("sqli",          run_sqli_module),
        "4": ("php2shell",     run_php2shell_module),
    }

    while True:
        try:
            clear_screen()
            banner_v2()
            show_menu()

            choice = safe_input("\n[?] Pilih opsi nomor: ").strip()

            if choice == "0":
                audit.log("system", "shutdown", "user_exit")
                print(f"\n[*] Keluar. Audit log tersimpan di: {audit.path}")
                return

            if choice not in modules:
                print("\n[!] Pilihan tidak valid.")
                safe_input("Tekan Enter untuk coba lagi...")
                continue

            name, fn = modules[choice]
            audit.log(name, "module_start", "running")
            print(f"\n[*] Menjalankan modul '{name}'...\n")

            try:
                result = fn()
                audit.log(name, "module_end", "ok", extra={
                    "return_type": type(result).__name__ if result is not None else "None",
                })
            except KeyboardInterrupt:
                print("\n[!] Modul dihentikan (Ctrl+C).")
                audit.log(name, "module_end", "interrupted")
                safe_input("Tekan Enter untuk kembali...")
            except Exception as e:
                print(f"\n[-] Error di modul '{name}': {e}")
                audit.log(name, "module_end", "error", extra={"error": str(e)})
                safe_input("Tekan Enter untuk kembali...")

        except KeyboardInterrupt:
            print("\n[*] Interrupt. Kembali ke menu...")
            continue
        except Exception as e:
            print(f"\n[!] Error tak terduga: {e}")
            safe_input("Tekan Enter...")
            continue

if __name__ == "__main__":
    main_menu_v2()
