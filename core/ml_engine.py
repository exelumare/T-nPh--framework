"""Machine Learning Inference Engine for TanPha V6 (Lightweight)."""
import os
import joblib # <--- Import library buat load model .pkl

class MLEngine:
    def __init__(self, model_path="ml_models/sqli_rf.pkl"):
        self.model_path = model_path
        self.model = None
        self.is_model_loaded = False
        
        # Coba load model kalau file-nya ada
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_model_loaded = True
                print(f"      [+] ML Model loaded from {self.model_path}")
            except Exception as e:
                print(f"      [-] Failed to load ML Model: {e}")
        else:
            print(f"      [*] ML Model not found at {self.model_path}. Using fallback Heuristic.")

    def extract_features(self, status_code, response_len, baseline_len, elapsed, baseline_elapsed, has_sql_error):
        """Ekstrak fitur dari response buat dimasukin ke AI."""
        return [
            status_code,
            abs(response_len - baseline_len), # Beda panjang
            elapsed - baseline_elapsed,       # Beda waktu (Delay)
            1 if has_sql_error else 0         # Ada error SQL? (1 = Iya, 0 = Tidak)
        ]

    def predict(self, features):
        """Prediksi pake model ML (kalau ada) atau fallback ke logika Heuristic."""
        if self.is_model_loaded and self.model:
            # Kalau model ML ada, pake AI beneran
            try:
                # Model sklearn.predict() balikin array, ambil index 0
                pred = self.model.predict([features])[0]
                # Probabilitas (kalau model support predict_proba)
                prob = self.model.predict_proba([features])[0][1] if hasattr(self.model, "predict_proba") else 0.9
                return bool(pred), prob
            except Exception as e:
                pass # Kalau error, fallback ke heuristic di bawah

        # === FALLBACK HEURISTIC (Buat jaga-jaga kalau model gagal load) ===
        status_code, len_diff, time_diff, has_error = features
        score = 0
        
        if status_code == 500: score += 50
        if len_diff > 50: score += 30
        if time_diff > 4.0: score += 50
        if has_error == 1: score += 40

        is_vuln = score >= 60
        confidence = min(score / 100.0, 0.99)
        
        return is_vuln, confidence
