import os
import sys
import json
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/chat"
AI_MODEL = "qwen2.5:7b" # Change to qwen2.5:7b if needed

SYSTEM_PROMPT = """You are an elite Incident Response (DFIR) Copilot and Malware Analyst.
You possess deep knowledge of Windows Internals (EPROCESS, PEB, VAD trees), standard Windows OS execution baselines, and rootkit evasion techniques.

Your goal is to correlate memory forensics artifacts and identify malicious activity.
Do not hallucinate. Base your findings ONLY on the provided JSON data. If a process name is spoofed, point it out.
"""

def load_artifact(filename):
    """Safely loads a JSON artifact file."""
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                return json.dumps(data, indent=2) if data else "[]"
            except json.JSONDecodeError:
                return "[Error: Invalid JSON]"
    return "[File Not Found or Empty]"

def build_correlation_prompt():
    """Builds the massive automated prompt containing all evidence and workflow instructions."""
    processes = load_artifact("filtered_processes.json")
    modules = load_artifact("filtered_modules.json")
    malfind = load_artifact("malfind.json")
    netscan = load_artifact("netscan.json")

    prompt = f"""Here are the cleaned artifacts extracted from a compromised Windows memory dump:

=== FILTERED PROCESSES ===
{processes}

=== FILTERED KERNEL MODULES ===
{modules}

=== MALFIND (INJECTIONS) ===
{malfind}

=== NETWORK CONNECTIONS ===
{netscan}

EXECUTE THE FOLLOWING WORKFLOW STEP-BY-STEP:
1. PROCESS ANALYSIS: Analyze the 'FILTERED PROCESSES' list. Identify any highly suspect processes based on abnormal parent-child relationships, missing execution flags, or suspicious command-line paths (e.g., svchost.exe running from Downloads).
2. CROSS-REFERENCE: Keep those suspect PIDs in mind. Look at the 'MALFIND', 'NETWORK CONNECTIONS', and 'FILTERED MODULES' data. Do any of your suspect PIDs have injected memory sections, active network connections, or associated hidden kernel modules?
3. CORRELATION REPORT: Print a final, highly detailed report to the analyst. Group the evidence by suspect PID/Activity. Explain EXACTLY why you believe it is malicious based on Windows Internals.
4. NEXT STEPS: Conclude by asking the analyst what specific aspect they want to dive into next.
"""
    return prompt

def _send_to_ollama(chat_history):
    """Sends the context to Qwen with an expanded context window."""
    payload = {
        "model": AI_MODEL,
        "messages": chat_history,
        "stream": False,
        "options": {
            "num_ctx": 32768,  # Unlocks Qwen's large context window (32k tokens)
            "temperature": 0.2 # Low temperature for analytical accuracy
        }
    }

    try:
        print("\n[*] Qwen 2.5 is analyzing and correlating artifacts (This may take a minute or two on local hardware)...")
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        response = urllib.request.urlopen(req)
        response_body = json.loads(response.read().decode('utf-8'))
        
        ai_message = response_body.get('message', {}).get('content', '')
        
        print("\n" + "=" * 80)
        print("                        AI CORRELATION REPORT")
        print("=" * 80)
        print(ai_message.strip())
        print("=" * 80)

        # Keep memory of the conversation
        chat_history.append({"role": "assistant", "content": ai_message})

    except urllib.error.URLError:
        print("\n[-] Error: Could not connect to Ollama. Ensure you ran 'ollama run qwen2.5:14b'")
        sys.exit(1)

def chat_with_copilot():
    print("\n" + "=" * 60)
    print("[*] INITIALIZING QWEN DFIR COPILOT...")
    print("=" * 60)

    # 1. Package all evidence and instructions
    initial_prompt = build_correlation_prompt()

    # 2. Setup chat history
    chat_history = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": initial_prompt}
    ]

    # 3. Fire the automated correlation workflow
    _send_to_ollama(chat_history)

    # 4. Drop into the interactive loop waiting for the analyst
    print("\n[*] Copilot is standing by. Type 'exit' to end the session.")
    while True:
        try:
            user_input = input("\n[Analyst] > ")
            if user_input.strip().lower() in ['exit', 'quit']:
                print("[*] Terminating Copilot session. Goodbye!")
                break
            if not user_input.strip():
                continue

            chat_history.append({"role": "user", "content": user_input})
            _send_to_ollama(chat_history)

        except KeyboardInterrupt:
            print("\n[*] Session interrupted.")
            break
