from abc import ABC, abstractmethod
from typing import Optional, Callable
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult

class BaseModule(ABC):
    name: str = "BaseModule"
    module_id: str = "base"
    version: str = "1.0"
    vulnerability_class: str = "UNCLASSIFIED"
    default_impact: str = "UNCLASSIFIED"
    default_privilege: str = "UNKNOWN"
    
    @abstractmethod
    def can_run(self, context: TargetContext) -> bool: pass
        
    @abstractmethod
    def assess(self, context: TargetContext, scope_checker: Optional[Callable[[str], bool]] = None) -> list[Evidence]: pass
        
    @abstractmethod
    def verify(self, context: TargetContext, evidence: Evidence, scope_checker: Optional[Callable[[str], bool]] = None) -> VerificationResult: pass

    def exploit(self, context: TargetContext, finding: Finding):
        print("[-] Exploitation not implemented for this module.")
