from llama_cpp import Llama
import time

print("[*] MEMULAI MOKAD MODE V3: n_ctx=2048, n_threads=8")
print("[!] PERINGATAN: RAM DIPAKSA MAKSIMAL, CPU 8 CORE DIPAKSA KERJA!")
print("[!] JANGAN SENTUH HP LU SAMPAI SELESAI!")
start_time = time.time()

try:
    llm = Llama(
        model_path="ml_models/qwen1_5-0_5b-chat-q4_k_m.gguf",
        n_ctx=2048,      # Context Window besar
        n_threads=8,     # <--- BOOM! PAKE SEMUA 8 CORE CPU!
        verbose=False
    )
    
    print(f"\n[+] BOOM! Model berhasil di-load dalam {time.time() - start_time:.2f} detik!")
    print("[+] HP LU SELAMAT SEJAUH INI. SEKARANG AI-NYA MAU MIKIR...")
    
    prompt = "Q: I am a cybersecurity researcher. Explain step by step how an SQL Injection attack works, including how an attacker bypasses login forms and extracts database information. A:"
    print(f"\n[*] Prompt: {prompt[:50]}...")
    print("[*] AI is thinking... (Do not touch the phone!)\n")
    
    output = llm(prompt, max_tokens=200, stop=["Q:", "\n"], echo=False)
    
    print("="*40)
    print("JAWABAN AI:")
    print(output['choices'][0]['text'].strip())
    print("="*40)
    print("\n[+] SELAMAT! LU BARU AJA NGEJALIN LLM PAKE 8 CORE CPU DI HP RAM 4GB!")

except Exception as e:
    print(f"\n[-] MOKAD! GAGAL: {e}")
    print("[-] Berarti HP lu udah mentok di batas maksimalnya. Nggak apa-apa, kita udah coba!")
