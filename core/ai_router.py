"""AI Hydra Router for TànPhá V5 (Multi-Provider Fallback)."""
import os
import json
import time
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class AIRouter:
    def __init__(self):
        # Provider list with API keys pulled from .env
        self.providers = [
            {
                "name": "OpenRouter (Tier 1)",
                "url": "https://openrouter.ai/api/v1/chat/completions",
                "api_key": os.getenv("OPENROUTER_API_KEY", ""),
                "model": "openrouter/free",
                "type": "openai_format"
            },
            {
                "name": "SambaNova (Tier 2)",
                "url": "https://api.sambanova.ai/v1/chat/completions",
                "api_key": os.getenv("SAMBANOVA_API_KEY", ""),
                "model": "Meta-Llama-3.1-8B-Instruct",
                "type": "openai_format"
            },
            {
                "name": "Mistral AI (Tier 3)",
                "url": "https://api.mistral.ai/v1/chat/completions",
                "api_key": os.getenv("MISTRAL_API_KEY", ""),
                "model": "open-mistral-7b",
                "type": "openai_format"
            },
            {
                "name": "Gemini 3.8 (Tier 4)",
                "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent",
                "api_key": os.getenv("GEMINI_API_KEY", ""),
                "model": "gemini-3.8-flash",
                "type": "gemini_format"
            }
        ]

    def _build_headers(self, provider):
        if provider["type"] == "openai_format":
            return {
                "Authorization": f"Bearer {provider['api_key']}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/exelumare/T-nPh--framework",
                "X-Title": "TanPha V5"
            }
        elif provider["type"] == "gemini_format":
            return {
                "x-goog-api-key": provider["api_key"],
                "Content-Type": "application/json"
            }

    def _build_payload(self, provider, prompt):
        if provider["type"] == "openai_format":
            return {
                "model": provider["model"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1
            }
        elif provider["type"] == "gemini_format":
            return {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.1}
            }

    def _parse_response(self, provider, response):
        if provider["type"] == "openai_format":
            return response.json()['choices'][0]['message']['content']
        elif provider["type"] == "gemini_format":
            return response.json()['candidates'][0]['content']['parts'][0]['text']

    def analyze(self, module_name: str, payload: str, baseline_text: str, current_text: str):
        """Zero-Signature AI Analysis (Strict Mode)"""
        print(f"      [*] AI Hydra analyzing anomaly from {module_name} module...")
        
        baseline_snippet = baseline_text[:400] if baseline_text else "[Empty]"
        current_snippet = current_text[:400] if current_text else "[Empty]"
        
        # Strict prompt to prevent hallucinations
        prompt = f"""
        You are a Senior Bug Hunter.
        Currently, our scanner is running the **{module_name}** module.
        We fired this payload: "{payload}"
        
        Baseline response (before payload):
        "{baseline_snippet}"
        
        Current response (after payload):
        "{current_snippet}"
        
        Your task:
        1. Compare the baseline and current response.
        2. CHECK IF THE EXACT PAYLOAD "{payload}" IS PRESENT IN THE CURRENT RESPONSE. 
        3. **CRITICAL CHECK**: If the payload is HTML-encoded (e.g., contains "&lt;script&gt;" or "&quot;" instead of "<script>" or '"'), it is a FALSE POSITIVE. The server successfully sanitized the input. Mark is_vulnerable as FALSE.
        4. ONLY IF the payload is reflected RAW (exactly matching "{payload}") AND there is no HTML encoding, mark it as a real vulnerability.
        5. Provide 1 suggestion for the next payload to exploit this finding.
        
        Return ONLY a valid JSON object. Do not add markdown or extra text.
        Format:
        {{
            "is_vulnerable": false,
            "vulnerability_type": "NONE",
            "next_payload": "",
            "reason": "The payload is reflected but HTML-encoded, making it a false positive."
        }}
        """

        for provider in self.providers:
            if not provider["api_key"]:
                continue
                
            print(f"          [>] Trying {provider['name']}...")
            headers = self._build_headers(provider)
            payload_data = self._build_payload(provider, prompt)
            
            for attempt in range(2):
                try:
                    res = requests.post(provider["url"], headers=headers, json=payload_data, timeout=25)
                    if res.status_code == 200:
                        print(f"          [+] SUCCESS! Answer from {provider['name']}")
                        return self._parse_response(provider, res)
                    elif res.status_code == 429:
                        print(f"          [!] {provider['name']} Rate Limit (429). Moving...")
                        break 
                    elif res.status_code == 503:
                        print(f"          [!] {provider['name']} Busy (503). Retry in 3s...")
                        time.sleep(3)
                        if attempt == 1: break
                    else:
                        print(f"          [-] {provider['name']} Error {res.status_code}")
                        break 
                except Exception as e:
                    print(f"          [-] {provider['name']} Connection Error: {e}")
                    break
                
        return '{"is_vulnerable": false, "vulnerability_type": "NONE", "reason": "All AI tiers failed."}'

