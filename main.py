import os
import sys
import argparse

# Import our custom modules
try:
    from core_triage import analyze_windows_dump
    from ai_copilot import chat_with_copilot
except ImportError as e:
    print(f"[-] Architecture Error: Missing project module: {e}")
    sys.exit(1)

BANNER = r"""
=========================================================================
   ____             _        _             __     __    _      _    ___
  / ___|__ _ _ __  | |_ __ _(_)_ __        \ \   / /__ | |    / \  |_ _|
 | |   / _` | '_ \ | __/ _` | | '_ \ _____  \ \ / / _ \| |   / _ \  | |
 | |__| (_| | |_) || || (_| | | | | |_____|  \ V / (_) | |__/ ___ \ | |
  \____\__,_| .__/  \__\__,_|_|_| |_|         \_/ \___/|___/_/   \_\___|
            |_|
                  Memory Forensics & DFIR Copilot
=========================================================================
"""

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Captain-VolatilitAI: Automated Volatility 3 Triage & Local AI Copilot"
    )
    
    parser.add_argument(
        "image",
        nargs="?",
        help="Path to the Windows memory dump file (.dmp, .raw, .vmem)"
    )
    
    parser.add_argument(
        "--skip-triage",
        action="store_true",
        help="Skip Volatility extraction and immediately launch the AI Copilot on existing JSON files."
    )
    
    parser.add_argument(
        "--triage-only",
        action="store_true",
        help="Run Volatility plugins and heuristic cleaning without launching the AI chat."
    )

    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_arguments()

    # --- Mode 1: Skip Triage (Direct AI Chat) ---
    if args.skip_triage:
        print("[*] '--skip-triage' detected: Skipping Volatility execution.")
        chat_with_copilot()
        return

    # --- Validate Memory Image Argument ---
    if not args.image:
        print("[-] Error: A path to a memory dump is required unless using '--skip-triage'.")
        print("    Usage: python main.py <path_to_memory_dump>")
        sys.exit(1)

    if not os.path.exists(args.image):
        print(f"[-] Error: File not found: '{args.image}'")
        sys.exit(1)

    # --- Mode 2: Full Extraction & Correlation ---
    try:
        print(f"[*] Target Image: {args.image}\n")
        analyze_windows_dump(args.image)
    except KeyboardInterrupt:
        print("\n[!] Triage process aborted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Fatal error during triage pipeline: {e}")
        sys.exit(1)

    # --- Mode 3: Triage Only ---
    if args.triage_only:
        print("\n[+] '--triage-only' specified. Artifacts saved. Exiting without AI.")
        return

    # --- Launch AI Copilot ---
    print("\n[+] Memory extraction and correlation completed successfully.")
    start_ai = input("\n[?] Ready to engage the DFIR AI Copilot? (Y/n): ").strip().lower()
    
    if start_ai in ('', 'y', 'yes'):
        chat_with_copilot()
    else:
        print("[*] Session closed. Cleaned JSON files remain available in current directory.")


if __name__ == "__main__":
    main()
