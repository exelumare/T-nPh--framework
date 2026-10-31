"""Authentication Engine for TanPha V3 (Global Auto Login)."""
import re


class AuthManager:
    def __init__(self, http_client):
        self.client = http_client

    def _extract_csrf(self, html, field_name=None):
        """Cari CSRF token di HTML."""
        if not html: return None, None
        
        if field_name:
            pattern = rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)["\']'
        else:
            pattern = r'name=["\']([^"\']*(?:token|csrf)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']'
        
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            if field_name:
                return field_name, match.group(1)
            else:
                return match.group(1), match.group(2)
        return None, None

    def _extract_submit(self, html):
        """Cari nama tombol submit (misal: Login, Submit, btnSubmit)."""
        if not html: return None, None
        
        pattern = r'<(?:input|button)[^>]*type=["\']submit["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        
        if match:
            return match.group(1), match.group(2)
            
        pattern2 = r'<(?:input|button)[^>]*name=["\']([^"\']*(?:login|submit|btn)[^"\']*)["\']'
        match2 = re.search(pattern2, html, re.IGNORECASE)
        if match2:
            return match2.group(1), "Submit"
            
        return None, None

    def auto_login(self, login_url, username, password, user_field="username", pass_field="password", csrf_field=None):
        """Global Auto Login Engine."""
        print(f"[*] Attempting Auto Login to: {login_url}")
        
        # 1. GET halaman login
        res = self.client.request("GET", login_url, bypass_mutation=True)
        if not res.success:
            print("[-] Failed to fetch login page.")
            return False

        # 2. Ekstrak CSRF token
        csrf_name, csrf_value = self._extract_csrf(res.response.text, csrf_field)
        if csrf_name and csrf_value:
            print(f"[+] CSRF Token found: {csrf_name}")
        else:
            print("[*] No CSRF token detected. Proceeding without it.")

        # 3. Ekstrak Tombol Submit
        submit_name, submit_value = self._extract_submit(res.response.text)
        if submit_name:
            print(f"[+] Submit button found: {submit_name}={submit_value}")
        else:
            print("[*] No submit button detected. Trying without it.")

        # 4. Siapin payload
        payload = {
            user_field: username,
            pass_field: password
        }
        if csrf_name and csrf_value:
            payload[csrf_name] = csrf_value
        if submit_name and submit_value:
            payload[submit_name] = submit_value

        # 5. POST login
        login_res = self.client.request("POST", login_url, data=payload, bypass_mutation=True)
        
        if not login_res.success:
            print("[-] Login request failed.")
            return False

        # 6. Cek apakah login berhasil (Redirect / Cookie / Teks 'logout')
        if login_res.response:
            if login_res.response.status_code in (301, 302):
                print(f"[+] LOGIN SUCCESS! (Redirected)")
                return True
            
            # Cek berdasarkan cookie session yang baru (misal PHPSESSID atau token)
            if len(self.client.session.cookies) > 0:
                print(f"[+] LOGIN SUCCESS! Session cookie established.")
                return True
                
            if "logout" in login_res.response.text.lower() or "welcome" in login_res.response.text.lower():
                print(f"[+] LOGIN SUCCESS! Dashboard detected.")
                return True
                
        print("[-] Login failed.")
        return False
