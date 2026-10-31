from dataclasses import dataclass
from typing import Optional
from enum import Enum

class EvasionLevel(Enum):
    NONE = 0
    STANDARD = 1
    AGGRESSIVE = 2

@dataclass
class HTTPConfig:
    proxy: Optional[str] = None
    cookie: Optional[str] = None
    delay: float = 0.5
    max_attempts: int = 3
    verify_tls: bool = True
    random_seed: Optional[int] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    evasion_level: EvasionLevel = EvasionLevel.STANDARD
