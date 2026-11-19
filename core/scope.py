import os
import json
import ipaddress
import re
import logging
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)

def parse_origin(url: str) -> Optional[Tuple[str, str, int]]:
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return None
            
        if "@" in parsed.netloc:
            return None
            
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return None
            
        try:
            host = host.encode('idna').decode('ascii')
        except Exception:
            return None
            
        try:
            ip = ipaddress.ip_address(host)
            host = str(ip)
        except ValueError:
            if re.match(r'^[0-9.]+$', host):
                return None
                
            pattern = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')
            if not pattern.match(host):
                return None
        
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80
            
        if type(port) is not int or not (0 < port < 65536):
            return None
            
        return scheme, host, port
    except (ValueError, TypeError, AttributeError): 
        return None

class ScopeManager:
    # List manual public suffix. BUKAN PSL lengkap, cuma mitigasi lokal.
    PUBLIC_SUFFIXES = {
        "co.uk", "com.au", "com.br", "co.jp", "co.in", "com.sg",
        "net.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
        "co.nz", "co.za", "com.mx", "com.ar", "com.tr"
    }

    def __init__(self, auth_file: str = ".tanpha_auth.json"):
        self.auth_file = auth_file
        self.saved_auths = self._load_auth_file()
        self.session_auths = {}

    def _load_auth_file(self) -> dict:
        if not os.path.exists(self.auth_file):
            return {}
        try:
            with open(self.auth_file, "r") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except json.JSONDecodeError as e:
            logger.error(f"Auth file {self.auth_file} is malformed JSON: {e}")
            return {}
        except PermissionError:
            logger.error(f"Permission denied reading auth file {self.auth_file}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error reading auth file {self.auth_file}: {e}")
            return {} 

    def check(self, url: str, module_id: str = "unknown") -> bool:
        if not isinstance(module_id, str) or not module_id.strip():
            return False
            
        origin = parse_origin(url)
        if not origin:
            return False
            
        scheme, host, port = origin

        # 1. Cek Session Auth
        key = (scheme, host, port)
        if key in self.session_auths:
            auth_data = self.session_auths[key]
            
            if not isinstance(auth_data, dict):
                del self.session_auths[key]
                return False
                
            exp = auth_data.get("expires_at")
            allowed = auth_data.get("allowed_modules")
            
            if not isinstance(exp, datetime):
                del self.session_auths[key]
                return False
                
            try:
                # Pastiin timezone beneran valid (bukan cuma tzinfo != None, tapi utcoffset() juga jalan)
                if exp.tzinfo is None or exp.utcoffset() is None:
                    del self.session_auths[key]
                    return False
                    
                if datetime.now(timezone.utc) < exp:
                    if allowed is not None:
                        if not isinstance(allowed, list) or not all(isinstance(m, str) and m.strip() for m in allowed):
                            del self.session_auths[key]
                            return False
                        if module_id not in allowed:
                            return False
                    return True
                else:
                    del self.session_auths[key]
            except Exception:
                # TANGKAP SEMUA EXCEPTION (termasuk RuntimeError dari custom tzinfo)
                del self.session_auths[key]
                return False

        # 2. Cek Saved Auth
        for saved_host, rules in self.saved_auths.items():
            if not isinstance(rules, dict) or not isinstance(saved_host, str):
                continue
                
            saved_host_norm = saved_host.lower().rstrip(".")
            try:
                saved_host_norm = saved_host_norm.encode('idna').decode('ascii')
            except Exception:
                continue 
            
            try:
                ip = ipaddress.ip_address(saved_host_norm)
                saved_host_norm = str(ip) 
                is_ip = True
            except ValueError:
                is_ip = False
                
            if not is_ip and not saved_host_norm.startswith("*."):
                pattern = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')
                if not pattern.match(saved_host_norm):
                    continue
            elif saved_host_norm.startswith("*."):
                domain_part = saved_host_norm[2:]
                
                if domain_part in self.PUBLIC_SUFFIXES:
                    continue
                    
                if "." not in domain_part:
                    continue
                    
                pattern = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')
                if not pattern.match(domain_part):
                    continue

            if saved_host_norm.startswith("*."):
                domain = saved_host_norm[2:]
                if not host.endswith("." + domain):
                    continue
            elif host != saved_host_norm:
                continue

            exp_str = rules.get("expires_at")
            req_scheme = rules.get("scheme")
            req_port = rules.get("port")
            allowed_mods = rules.get("allowed_modules")

            if not isinstance(exp_str, str) or not isinstance(req_scheme, str) or type(req_port) is not int:
                continue
                
            if req_scheme != scheme or req_port != port:
                continue

            try:
                if exp_str.endswith("Z"):
                    exp_str = exp_str[:-1] + "+00:00"
                exp = datetime.fromisoformat(exp_str)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    continue 
            except (ValueError, TypeError):
                continue 

            if allowed_mods is not None:
                if not isinstance(allowed_mods, list) or not all(isinstance(m, str) and m.strip() for m in allowed_mods):
                    continue
                if module_id not in allowed_mods:
                    continue
            
            return True

        return False

    def approve_session(self, url: str, duration_minutes: int = 120, allowed_modules: Optional[List[str]] = None):
        if type(duration_minutes) is not int or duration_minutes <= 0:
            raise ValueError("duration_minutes must be a positive integer")
            
        if allowed_modules is not None:
            if not isinstance(allowed_modules, list) or not all(isinstance(m, str) and m.strip() for m in allowed_modules):
                raise ValueError("allowed_modules must be a list of non-empty strings")
                
        origin = parse_origin(url)
        if not origin:
            raise ValueError(f"Invalid URL for authorization: {url}")
            
        scheme, host, port = origin
        key = (scheme, host, port)
        self.session_auths[key] = {
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=duration_minutes),
            "allowed_modules": allowed_modules
        }
        return key
