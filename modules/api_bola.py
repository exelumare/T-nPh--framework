"""Auto-BOLA Hunter V2 for TanPha. Handles UUIDs, Query Params, and JSON Structure Validation."""
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus

class APIBolaModule(BaseModule):
    name = "APIBOLA"
    module_id = "api_bola"
    version = "2.0 (Smart IDOR)"
    vulnerability_class = "BROKEN_OBJECT_LEVEL_AUTHORIZATION"

    def __init__(self):
        super().__init__()

    def can_run(self, context: TargetContext) -> bool:
        return True

    def _extract_keys(self, data):
        """Ekstrak keys dari JSON (buat validasi struktur)."""
        if isinstance(data, dict):
            return set(data.keys())
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            return set(data[0].keys())
        return set()

    def _mutate_url(self, target_url, original_id, new_id):
        """Ngubah ID baik di Path maupun Query Parameter."""
        parsed = urlparse(target_url)
        
        # 1. Cek apakah ID ada di Path
        if str(original_id) in parsed.path:
            new_path = parsed.path.replace(str(original_id), str(new_id))
            return urlunparse(parsed._replace(path=new_path))
            
        # 2. Cek apakah ID ada di Query Parameter (misal ?id=123)
        query_params = parse_qs(parsed.query)
        mutated = False
        for key, values in query_params.items():
            if str(original_id) in values:
                query_params[key] = [str(new_id)]
                mutated = True
                break
                
        if mutated:
            new_query = urlencode(query_params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
            
        # 3. Fallback: Kalau nggak ketemu di path/query, append ke ujung
        if parsed.path.endswith('/'):
            new_path = f"{parsed.path}{new_id}"
        else:
            new_path = f"{parsed.path}/{new_id}"
        return urlunparse(parsed._replace(path=new_path))

    def assess(self, context: TargetContext, auth_checker=None) -> list:
        evidence_pool = []
        target_url = context.target.base_url
        
        print(f"      [>] Starting Auto-BOLA Hunt on '{target_url}'...")
        
        # 1. Fetch Baseline
        res = context.http_client.request("GET", target_url, auth_checker=auth_checker)
        if not res or not res.success or not res.response:
            print("          [-] Gagal konek ke API.")
            return evidence_pool
            
        try:
            baseline_data = res.response.json()
        except json.JSONDecodeError:
            print("          [-] Response bukan JSON, skip BOLA.")
            return evidence_pool

        baseline_keys = self._extract_keys(baseline_data)
        if not baseline_keys:
            print("          [-] JSON kosong atau format tidak dikenali.")
            return evidence_pool

        # 2. Extract ID (Support Int, String Digit, UUID)
        extracted_id = None
        # Cari key yang biasanya nyimpen ID
        search_keys = ["id", "user_id", "uuid", "account_id", "slug"]
        
        # Handle List vs Dict
        target_obj = baseline_data[0] if isinstance(baseline_data, list) and len(baseline_data) > 0 else baseline_data
        
        if isinstance(target_obj, dict):
            for k in search_keys:
                if k in target_obj:
                    extracted_id = target_obj[k]
                    break

        if not extracted_id:
            print("          [-] Tidak ada 'id' yang bisa diuji otomatis.")
            return evidence_pool
            
        print(f"          [+] Found ID: {extracted_id}. Testing BOLA...")

        # 3. Bikin ID palsu
        test_id = None
        if isinstance(extracted_id, int):
            test_id = extracted_id + 1
        elif isinstance(extracted_id, str):
            if extracted_id.isdigit():
                # Kalau string angka "123" -> jadi "124"
                test_id = str(int(extracted_id) + 1)
            elif len(extracted_id) > 1:
                # Kalau UUID/Slug, coba ganti karakter terakhir (Brute force simpel)
                test_id = extracted_id[:-1] + ('a' if extracted_id[-1] != 'a' else 'b')
        
        if not test_id or test_id == extracted_id:
            print("          [-] Gagal membuat ID mutasi (Format terlalu kompleks).")
            return evidence_pool

        # 4. Mutasi URL & Tembak
        bola_url = self._mutate_url(target_url, extracted_id, test_id)
        print(f"          [>] Testing BOLA URL: {bola_url}")
        
        bola_res = context.http_client.request("GET", bola_url, auth_checker=auth_checker)
        
        # 5. Validasi Ketat
        if bola_res and bola_res.success and bola_res.response:
            if bola_res.response.status_code == 200:
                try:
                    bola_data = bola_res.response.json()
                    bola_keys = self._extract_keys(bola_data)
                    
                    # Cek 1: Struktur JSON harus mirip (ada key yang sama)
                    # Cek 2: Jangan anggap error message sebagai data valid
                    is_error = any(k in bola_keys for k in ["error", "message", "status"]) and len(bola_keys) <= 2
                    
                    if baseline_keys.intersection(bola_keys) and not is_error:
                        print(f"          [!] WARNING: Akses ID {test_id} berhasil & Struktur JSON Valid!")
                        evidence_pool.append(Evidence(
                            attempt_id="bola_found", module_id=self.module_id, module_version=self.version,
                            location=bola_url, parameter=str(extracted_id), outcome="OBSERVED",
                            reason_code="BOLA_POTENTIAL", reason_detail=f"Data ID {test_id} bisa diakses & memiliki struktur valid.",
                            confidence=0.9, evidence_text="Potential BOLA detected", assess_payload=str(test_id)
                        ))
                    else:
                        print(f"          [-] Aman: ID {test_id} ngasih error/kosong.")
                        
                except json.JSONDecodeError:
                    print(f"          [-] Response bukan JSON (Mungkin HTML error).")
            elif bola_res.response.status_code in (401, 403):
                print(f"          [-] Aman: ID {test_id} dilindungi (Status {bola_res.response.status_code}).")
            elif bola_res.response.status_code == 404:
                print(f"          [-] Aman: ID {test_id} tidak ditemukan (Status 404).")

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "BOLA_POTENTIAL":
            return VerificationResult(
                VerificationStatus.INCONCLUSIVE, 0.9, "NEEDS_MANUAL_REVIEW",
                "Akses data ID lain berhasil dengan struktur JSON valid. Cek manual untuk konfirmasi.",
                verify_payload=evidence.assess_payload
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")
