from core.oob_manager import OOBManager

def main():
    print("[*] Testing OOB Engine...")
    oob = OOBManager()
    
    # 1. Generate URL
    payload_url = oob.generate_payload()
    if not payload_url:
        print("[-] Gagal generate URL. Cek koneksi internet atau status code di atas.")
        return
        
    print(f"\n[!] ACTION REQUIRED: Buka link ini di browser HP lu untuk simulasi 'korban':")
    print(f"    {payload_url}")
    
    # 2. Cek apakah ada hit (karena lu buka di browser, harusnya ke-detect)
    hit = oob.check_hits(timeout=15)
    
    if hit:
        print("\n[+] SUCCESS! Mesin OOB berfungsi. TànPhá bisa mendeteksi Blind Vulnerability!")
    else:
        print("\n[-] FAILED. Nggak ada koneksi masuk. Cek koneksi internet lu.")

if __name__ == "__main__":
    main()
