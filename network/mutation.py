import random
import urllib.parse
from typing import Dict, Any
from network.config import EvasionLevel

class RequestMutator:
    def __init__(self, level: EvasionLevel, rng: random.Random):
        self.level = level
        self.rng = rng

    def mutate_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        mutated = dict(headers)
        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            mutated.update({"X-Forwarded-For": "127.0.0.1", "X-Originating-IP": "127.0.0.1"})
        return mutated

    def mutate_url_parameters(self, url: str, target_param: str = None) -> str:
        if self.level == EvasionLevel.NONE: return url
        parsed = urllib.parse.urlparse(url)
        if not parsed.query: return url
        
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        mutated_qs = []
        for k, v in qs:
            if target_param is None or k == target_param:
                if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
                    v = v.replace(" ", "/**/")
                    for w in ["SELECT", "UNION", "AND", "OR"]:
                        if w in v.upper():
                            mix = ''.join(c.upper() if self.rng.choice([True, False]) else c.lower() for c in w)
                            v = v.replace(w, mix).replace(w.lower(), mix)
                if self.level == EvasionLevel.AGGRESSIVE:
                    v = urllib.parse.quote(urllib.parse.quote(v))
            mutated_qs.append((k, v))
            
        new_query = urllib.parse.urlencode(mutated_qs, safe="")
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
