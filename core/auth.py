"""Authentication Engine - F-11: Protected Resource Only."""
import re

class AuthManager:
    def __init__(self, http_client, auth_checker, protected_paths=None):
        self.client = http_client
        self.auth_checker = auth_checker
        # FIX: Tambahin /index.php dan / buat DVWA
        self.protected_paths = protected_paths or [
            "/index.php", "/", "/dashboard", "/profile", "/account", "/admin", "/user", "/settings"
        ]

    def _extract_csrf(self, html, field_name=None):
        if not html: return None, None
        if field_name:
            pattern = rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)["\']'
        else:
            pattern = r'name=["\']([^"\']*(?:token|csrf)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            if field_name: return field_name, match.group(1)
            return match.group(1), match.group(2)
        return None, None

    def _extract_submit(self, html):
        if not html: return None, None
        pattern = r'<(?:input|button)[^>]*type=["\']submit["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        if match: return match.group(1), match.group(2)
        pattern2 = r'<(?:input|button)[^>]*name=["\']([^"\']*(?:login|submit|btn)[^"\']*)["\']'
        match2 = re.search(pattern2, html, re.IGNORECASE)
        if match2: return match2.group(1), "Submit"
        return None, None

    def _verify_via_protected_endpoint(self, base_url):
        for path in self.protected_paths:
            test_url = base_url.rstrip("/") + path
            try:
                res = self.client.request("GET", test_url, auth_checker=self.auth_checker, bypass_mutation=True)
                if not res.success or not res.response:
                    continue
                if res.response.url and "login" in res.response.url.lower():
                    return False
                if 200 <= res.response.status_code < 300:
                    text = res.response.text
                    if re.search(r'<input[^>]*type=["\']password["\']', text, re.IGNORECASE):
                        continue
                    has_logout = bool(re.search(r'(logout|sign[\s_-]*out|log[\s_-]*out)', text, re.IGNORECASE))
                    has_dashboard = bool(re.search(r'(dashboard|welcome|profile|home)', text, re.IGNORECASE))
                    if has_logout or has_dashboard:
                        print(f"[+] Protected resource accessible: {test_url}")
                        return True
            except Exception:
                continue
        return False

    def _is_login_success(self, response, base_url):
        if not response: return False
        if response.status_code < 200 or response.status_code >= 300:
            return False
        return self._verify_via_protected_endpoint(base_url)

    def auto_login(self, login_url, username, password, user_field="username", pass_field="password", csrf_field=None):
        print(f"[*] Attempting Auto Login to: {login_url}")
        res = self.client.request("GET", login_url, auth_checker=self.auth_checker, bypass_mutation=True)
        if not res.success or not res.response:
            print("[-] Failed to fetch login page.")
            return False

        csrf_name, csrf_value = self._extract_csrf(res.response.text, csrf_field)
        submit_name, submit_value = self._extract_submit(res.response.text)

        payload = {user_field: username, pass_field: password}
        if csrf_name and csrf_value: payload[csrf_name] = csrf_value
        if submit_name and submit_value: payload[submit_name] = submit_value

        login_res = self.client.request("POST", login_url, data=payload, auth_checker=self.auth_checker, bypass_mutation=True)
        if not login_res.success or not login_res.response:
            print("[-] Login request failed.")
            return False

        base_url = login_url.rsplit("/", 1)[0] + "/"
        if self._is_login_success(login_res.response, base_url):
            print(f"[+] LOGIN SUCCESS! (Protected resource verified)")
            return True
        print("[-] Login failed (no protected resource accessible).")
        return False
