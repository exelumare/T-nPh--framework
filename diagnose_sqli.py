import re
import time
from functools import partial
from urllib.parse import urljoin

from network.config import HTTPConfig, EvasionLevel
from network.client import HTTPClient
from core.scope import ScopeManager
from core.auth import AuthManager

def run_diagnostic():
    target_url = input("[?] Enter target URL (e.g., http://IP/vulnerabilities/sqli/): ").strip()
    login_url = input("[?] Enter login URL (e.g., http://IP/login.php): ").strip()
    
    if not target_url or not login_url:
        print("[-] URL cannot be empty.")
        return

    config = HTTPConfig(verify_tls=False, evasion_level=EvasionLevel.NONE, delay=0.5)
    scope = ScopeManager()
    scope.approve_session(target_url, allowed_modules=["setup", "diagnostic", "baseline"])
    
    client = HTTPClient(config)
    auth_checker = partial(scope.check, module_id="diagnostic")
    setup_checker = partial(scope.check, module_id="setup")

    print("\n=============================================")
    print(" [1] AUTHENTICATION")
    print("=============================================")
    auth = AuthManager(client, auth_checker=setup_checker)
    if not auth.auto_login(login_url, "admin", "password"):
        print("[-] Login failed. Aborting diagnostic.")
        client.close()
        return
    
    print("\n=============================================")
    print(" [2] GET PARENT DOCUMENT (index.php)")
    print("=============================================")
    parent_url = urljoin(target_url, "index.php") if "sqli" in target_url else target_url
    print(f"[*] URL: {parent_url}")
    
    res_parent = client.request("GET", parent_url, auth_checker=auth_checker)
    if not res_parent.success or not res_parent.response:
        print("[-] Failed to get parent document.")
        client.close()
        return
        
    resp_p = res_parent.response
    print(f"[*] Status       : {resp_p.status_code}")
    print(f"[*] Final URL    : {resp_p.url}")
    print(f"[*] Content-Type : {resp_p.headers.get('Content-Type', 'Unknown')}")
    print(f"[*] Body Bytes   : {len(resp_p.content)}")

    print("\n=============================================")
    print(" [3] PARSE IFRAME")
    print("=============================================")
    iframe_match = re.search(r'<iframe[^>]*src=["\']([^"\']+)["\']', resp_p.text, re.IGNORECASE)
    if not iframe_match:
        print("[-] No iframe found in parent HTML.")
        print("[*] HTML Snippet:", resp_p.text[:200].replace('\n', ' '))
        client.close()
        return
        
    iframe_src = iframe_match.group(1)
    print(f"[+] Found iframe src : {iframe_src}")
    
    # Resolve relative URL
    iframe_url = urljoin(parent_url, iframe_src)
    print(f"[+] Resolved URL     : {iframe_url}")

    print("\n=============================================")
    print(" [4] GET IFRAME DOCUMENT")
    print("=============================================")
    res_iframe = client.request("GET", iframe_url, auth_checker=auth_checker)
    if not res_iframe.success or not res_iframe.response:
        print("[-] Failed to get iframe document.")
        client.close()
        return
        
    resp_i = res_iframe.response
    print(f"[*] Status       : {resp_i.status_code}")
    print(f"[*] Final URL    : {resp_i.url}")
    print(f"[*] Content-Type : {resp_i.headers.get('Content-Type', 'Unknown')}")
    print(f"[*] Body Bytes   : {len(resp_i.content)}")
    
    if len(resp_i.content) == 0:
        print("[-] WARNING: Iframe body is EMPTY.")
        print("[*] Redirect History:", [r.status_code for r in resp_i.history])
        if "Location" in resp_i.headers:
            print("[*] Location Header:", resp_i.headers["Location"])

    print("\n=============================================")
    print(" [5] EXTRACT CSRF TOKEN & PREPARE POST")
    print("=============================================")
    csrf_token = None
    csrf_match = re.search(r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']', resp_i.text, re.IGNORECASE)
    if csrf_match:
        csrf_token = csrf_match.group(1)
        print(f"[+] CSRF Token found: {csrf_token[:8]}...")
    else:
        print("[-] No CSRF token found in iframe HTML.")

    post_data = {"id": "1", "Submit": "Submit"}
    if csrf_token:
        post_data["user_token"] = csrf_token

    print("\n=============================================")
    print(" [6] POST PAYLOAD TO IFRAME")
    print("=============================================")
    headers = {
        "Referer": parent_url,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    start_post = time.time()
    res_post = client.request("POST", iframe_url, data=post_data, headers=headers, auth_checker=auth_checker)
    elapsed_post = time.time() - start_post
    
    if res_post.success and res_post.response:
        resp_post = res_post.response
        print(f"[*] Status       : {resp_post.status_code}")
        print(f"[*] Final URL    : {resp_post.url}")
        print(f"[*] Content-Type : {resp_post.headers.get('Content-Type', 'Unknown')}")
        print(f"[*] Body Bytes   : {len(resp_post.content)}")
        print(f"[*] Location     : {resp_post.headers.get('Location', 'None')}")
        print(f"[*] Time Elapsed : {elapsed_post:.2f}s")
        print("[*] Redirect History:", [r.status_code for r in resp_post.history])
    else:
        print(f"[-] POST failed: {res_post.error}")

    print("\n=============================================")
    print(" [7] SESSION INSPECTOR")
    print("=============================================")
    print(f"[*] Session ID Object : {id(client.session)}")
    cookies = client.session.cookies.get_dict()
    print(f"[*] Cookies in Jar    : {list(cookies.keys())}")
    if "Cookie" in client.session.headers:
        print(f"[*] Manual Cookie Hdr : YES (Potential Conflict)")
    else:
        print(f"[*] Manual Cookie Hdr : NO")
        
    print("\n[*] Diagnostic Complete.")
    client.close()

if __name__ == "__main__":
    run_diagnostic()
