"""Heuristic Scoring Engine for TanPha V5."""

class HeuristicEngine:
    def __init__(self, threshold=50):
        self.threshold = threshold

    def analyze(self, status_code, response_text, elapsed, baseline_status, baseline_text):
        score = 0
        reasons = []

        # 1. Analisis Perubahan Status Code
        if status_code != baseline_status:
            if status_code == 500:
                score += 50
                reasons.append("HTTP 500 Internal Server Error")
            elif status_code == 403:
                score += 30
                reasons.append("HTTP 403 Forbidden (Protected Resource)")
        
        # 2. Analisis Delay (Time-Based)
        if elapsed >= 5.0:
            score += 60
            reasons.append(f"Time Delay ({elapsed:.2f}s)")

        # 3. Analisis Signature Error (SQLi, LFI, dll)
        error_signatures = [
            "sql syntax", "mysql", "unclosed quotation", 
            "root:x:0:0", "warning: include", "failed to open stream"
        ]
        if response_text and any(sig in response_text.lower() for sig in error_signatures):
            score += 50
            reasons.append("Known Error Signature Found")

        # 4. Analisis Perbedaan Panjang Teks (Boolean/Reflected)
        if baseline_text and response_text:
            diff = abs(len(baseline_text) - len(response_text))
            if diff > 50:
                score += 20
                reasons.append(f"Large Response Diff ({diff} chars)")
            elif diff > 10:
                score += 10
                reasons.append(f"Small Response Diff ({diff} chars)")

        # 5. Cek WAF (Kalau kena block)
        if status_code in (429, 406) or "cloudflare" in (response_text or "").lower():
            score -= 20
            reasons.append("WAF/Rate Limit Detected (Penalty)")

        # Tentukan Status (Validated / Rejected)
        is_valid = score >= self.threshold
        confidence = min(score / 100.0, 1.0)

        return {
            "is_valid": is_valid,
            "score": score,
            "confidence": round(confidence, 2),
            "reasons": " | ".join(reasons)
        }
