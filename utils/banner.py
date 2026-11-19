import time
import sys
import os
import platform
import subprocess
import random
import shutil

# ANSI Colors
CYAN = '\033[96m'
RED = '\033[91m'
YELLOW = '\033[93m'
MAGENTA = '\033[95m'
GREEN = '\033[92m'
WHITE = '\033[97m'
RESET = '\033[0m'
BOLD = '\033[1m'
CLEAR = '\033[2J\033[H'

def show_warning_sequence():
    """Phase 1: Large warning with flashing red screen."""
    term = shutil.get_terminal_size()
    w, h = term.columns, term.lines

    warning_art = [
        "          ▄▄▄▄▄▄▄▄▄▄▄          ",
        "        ▄█████████████▄        ",
        "       █████████████████       ",
        "      ███████████████████      ",
        "     █████████████████████     ",
        "    ███████████████████████    ",
        "   ███████████   ███████████   ",
        "   ███████████   ███████████   ",
        "  ████████████   ████████████  ",
        "  ████████████   ████████████  ",
        " █████████████   █████████████ ",
        " █████████████   █████████████ ",
        " █████████████   █████████████ ",
        " █████████████   █████████████ ",
        "███████████████████████████████",
        "███████████████████████████████",
        "██████████████   ██████████████",
        "███████████████████████████████"
    ]

    art_w = len(warning_art[0])
    pad = " " * max(0, (w - art_w) // 2)
    v_pad = "\n" * max(0, (h - len(warning_art) - 5) // 2)

    text_box = "╔══════════════════════════════╗\n║  S Y S T E M  C O R R U P T E D  ║\n╚══════════════════════════════╝"
    tb_lines = text_box.splitlines()
    tb_w = len(tb_lines[0])
    tb_pad = " " * max(0, (w - tb_w) // 2)

    # Blink 3 times
    for _ in range(3):
        # Red Background, White Text
        sys.stdout.write("\033[41m\033[97m\033[2J\033[H")
        print(v_pad, end="")
        for line in warning_art:
            print(f"{pad}{line}")
        print("\n")
        for line in tb_lines:
            print(f"{tb_pad}{line}")
        sys.stdout.flush()
        time.sleep(0.3) # <--- ADJUST BLINK SPEED HERE

        # Black Background, Red Text
        sys.stdout.write("\033[40m\033[91m\033[2J\033[H")
        print(v_pad, end="")
        for line in warning_art:
            print(f"{pad}{line}")
        print("\n")
        for line in tb_lines:
            print(f"{tb_pad}{line}")
        sys.stdout.flush()
        time.sleep(0.3) # <--- ADJUST BLINK SPEED HERE

    # Simulate Crash
    sys.stdout.write("\033[0m\033[2J\033[H")
    print(f"{YELLOW}Kernel Panic - Not syncing: Attempted to kill init!{RESET}")
    time.sleep(0.8)
    sys.stdout.write(CLEAR)

def dvd_bounce_animation(duration=8):
    """Phase 2: Bouncing DVD logo animation using large ASCII art."""
    term = shutil.get_terminal_size()
    w, h = term.columns, term.lines
    
    # Large ASCII Art (6 lines)
    dvd_art = [
        "████████╗ █████╗ ███╗   ██╗██████╗ ██╗  ██╗ █████╗ ",
        "╚══██╔══╝██╔══██╗████╗  ██║██╔══██╗██║  ██║██╔══██╗",
        "   ██║   ███████║██╔██╗ ██║██████╔╝███████║███████║",
        "   ██║   ██╔══██║██║╚██╗██║██╔═══╝ ██╔══██║██╔══██║",
        "   ██║   ██║  ██║██║ ╚████║██║     ██║  ██║██║  ██║",
        "   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝"
    ]
    
    text_w = max(len(line) for line in dvd_art)
    text_h = len(dvd_art)
    
    # Fallback if terminal is too small
    if w < text_w + 5:
        dvd_art = [
            "╔╦╗╔═╗╔╗╔╔═╗╦ ╦╔═╗",
            " ║ ╠═╣║║║╠═╝╠═╣╠═╣",
            " ╩ ╩ ╩╝╚╝╩  ╩ ╩╩ ╩"
        ]
        text_w = max(len(line) for line in dvd_art)
        text_h = len(dvd_art)
    
    x, y = 5, 5
    dx, dy = 1, 1
    colors = [CYAN, RED, YELLOW, MAGENTA, GREEN, WHITE]
    c_idx = 0
    
    end_time = time.time() + duration
    sys.stdout.write("\033[?25l\033[2J\033[H") # Hide cursor, clear screen
    
    prev_x, prev_y = None, None
    
    while time.time() < end_time:
        # Clear previous frame
        if prev_x is not None:
            for i in range(text_h):
                if 0 < prev_y + i < h:
                    sys.stdout.write(f"\033[{prev_y + i};1H" + " " * w)
            
        # Print new frame
        for i, line in enumerate(dvd_art):
            if 0 < y + i < h:
                sys.stdout.write(f"\033[{y + i};{x}H{colors[c_idx]}{BOLD}{line}{RESET}")
        sys.stdout.flush()
        
        prev_x, prev_y = x, y
        
        x += dx
        y += dy
        
        # Check boundaries
        if x <= 1 or x + text_w >= w:
            dx *= -1
            c_idx = (c_idx + 1) % len(colors)
            x = max(1, min(x, w - text_w - 1)) 
            
        if y <= 1 or y + text_h >= h:
            dy *= -1
            c_idx = (c_idx + 1) % len(colors)
            y = max(1, min(y, h - text_h - 1))
            
        time.sleep(0.05) # <--- ADJUST BOUNCE SPEED HERE (Lower is faster)
        
    sys.stdout.write("\033[?25h\033[2J\033[H") # Show cursor, clear screen

def boot_sequence():
    show_warning_sequence()
    dvd_bounce_animation(8) 
    
    sys.stdout.write(CLEAR)
    print(f"{YELLOW}{BOLD}>> REBOOTING SYSTEM <<{RESET}")
    time.sleep(0.5)
    print(f"{CYAN}Loading TànPhá OS v5.0...{RESET}")
    time.sleep(1)
    sys.stdout.write(CLEAR)

def print_banner():
    print(f"{RED}{BOLD}=== TÀNPHÁ V5 ==={RESET}")
    print(f"{CYAN}[ Enterprise Pentest Framework ]{RESET}\n")

def get_chafa_logo():
    if os.path.exists("logo.png"):
        try:
            result = subprocess.run(
                ["chafa", "logo.png", "--size=60x30", "--symbols=block"],
                capture_output=True, text=True, check=True
            )
            return result.stdout.splitlines()
        except Exception:
            return [f"{RED}[ Error loading logo.png ]{RESET}"]
    else:
        return [f"{RED}[ logo.png not found ]{RESET}"]

def show_main_menu():
    boot_sequence()
    sys.stdout.write(CLEAR)
    
    logo_lines = get_chafa_logo()
    python_ver = platform.python_version()
    
    info_lines = [
        f"{CYAN}{BOLD}root@tanpha{RESET}",
        f"{CYAN}-----------{RESET}",
        f"{CYAN}OS{RESET}      : TànPhá OS v5.0",
        f"{CYAN}Host{RESET}    : Exelumare Framework",
        f"{CYAN}Kernel{RESET}  : Python {python_ver}",
        f"{CYAN}Shell{RESET}   : bash 5.x (Termux)",
        f"{CYAN}Status{RESET}  : {RED}Weaponized{RESET}",
        f"{CYAN}Modules{RESET} : 6 Loaded",
        f"{CYAN}Author{RESET}  : Exelumare",
        f"{CYAN}Repo{RESET}    : github.com/exelumare"
    ]
    
    max_lines = max(len(logo_lines), len(info_lines))
    for i in range(max_lines):
        left = logo_lines[i] if i < len(logo_lines) else " " * 60
        right = info_lines[i] if i < len(info_lines) else ""
        print(f"{left}    {right}")
        
    print("\n" + "="*45)
    print(f"{YELLOW}{BOLD}   TÀNPHÁ OS v5.0 - MAIN MENU{RESET}")
    print("="*45)
    print(f"  [{CYAN}1{RESET}] Full Scan (All Modules)")
    print(f"  [{CYAN}2{RESET}] SQL Injection Scanner")
    print(f"  [{CYAN}3{RESET}] Command Injection Scanner")
    print(f"  [{CYAN}4{RESET}] LFI Scanner")
    print(f"  [{CYAN}5{RESET}] XSS Scanner")
    print(f"  [{CYAN}6{RESET}] Recon (Sensitive Files)")
    print(f"  [{RED}0{RESET}] Exit\n")

    while True:
        try:
            choice = input(f"{GREEN}root@tanpha{RESET}:{CYAN}~{RESET}# ").strip()
            
            if choice in ["0", "1", "2", "3", "4", "5", "6"]:
                if choice == "0":
                    print(f"{RED}Exiting...{RESET}")
                    sys.exit(0)
                
                module_map = {
                    "1": "full", "2": "sqli", "3": "cmd", 
                    "4": "lfi", "5": "xss", "6": "recon"
                }
                selected = module_map[choice]
                
                target = input(f"{YELLOW}[?] Enter Target URL: {RESET}").strip()
                if target:
                    return selected, target
                else:
                    print(f"{RED}[!] URL cannot be empty. Try again.{RESET}\n")
            else:
                print(f"{RED}[!] Invalid module. Select 0-6.{RESET}\n")
        except KeyboardInterrupt:
            print(f"\n{RED}Exiting...{RESET}")
            sys.exit(0)
