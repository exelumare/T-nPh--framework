"""
Audit Log — JSONL append-only.

Tujuan:
  - Mencatat setiap aksi yang dilakukan tool (module_start, module_end, error).
  - Melindungi USER secara hukum: bukti bahwa pemakaian dilakukan dengan
    operator yang jelas, waktu yang jelas, target yang jelas.
  - Tidak mencatat payload atau data sensitif — hanya metadata operasional.

Format: logs/audit_YYYYMMDD.jsonl
Satu baris = satu event.
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, operator: str, log_dir: str = "logs"):
        self.operator = operator or "anonymous"
        self.session_id = str(uuid.uuid4())
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        date_tag = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.log_path = os.path.join(log_dir, f"audit_{date_tag}.jsonl")

    def log(self, module: str, action: str, result: str, extra: dict = None) -> None:
        """
        Tulis satu event ke audit log.
        module : 'sqli' | 'upload' | 'cmd_injection' | 'php2shell' | 'system'
        action : 'module_start' | 'module_end' | 'shutdown' | ...
        result : 'ok' | 'error' | 'interrupted' | 'running' | ...
        extra  : dict bebas — JANGAN taruh payload / credential di sini.
        """
        event = {
            "ts":       datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "epoch":    int(time.time()),
            "session":  self.session_id,
            "operator": self.operator,
            "module":   module,
            "action":   action,
            "result":   result,
        }
        if extra:
            # Batasi: jangan masukkan password / token / payload mentah
            safe_extra = {}
            for k, v in extra.items():
                if any(s in k.lower() for s in ("password", "token", "secret", "cookie", "auth")):
                    safe_extra[k] = "***redacted***"
                else:
                    safe_extra[k] = v
            event["extra"] = safe_extra

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            # Audit log TIDAK boleh membuat tool crash.
            pass

    @property
    def path(self) -> str:
        return self.log_path
