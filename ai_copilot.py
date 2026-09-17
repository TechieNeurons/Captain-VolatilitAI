import os
import json
import urllib.request
from core_triage import build_windows_plugin_catalog

OLLAMA_URL = "http://localhost:11434/api/chat"
AI_MODEL = "qwen2.5:7b"

# Load the exact Volatility 3 catalog directly from the framework
PLUGIN_CATALOG = build_windows_plugin_catalog()
CATALOG_PREVIEW = "\n".join([f"- {name}: {desc}" for name, desc in PLUGIN_CATALOG.items()])

SYSTEM_PROMPT = f"""You are Captain-VolAI, an autonomous DFIR Memory Forensics Agent.
You possess deep, pre-trained knowledge of Windows Internals (EPROCESS blocks, PEB/TEB, VAD trees, Object Manager, Registry hives, etc.).

YOUR DIRECTIVES:
1. Volatility 2 IS OBSOLETE. Never use `--profile` or legacy commands.
2. YOU CANNOT RUN COMMANDS DIRECTLY. You can only propose them to the human analyst.
3. NO HALLUCINATIONS. Never fake execution outputs.

THE REASONING ENGINE (HOW YOU MUST THINK):
When the analyst asks a question or you spot an anomaly, you must autonomously figure out how to solve it using this thought process:
- Step 1 (OS Architecture): Think about WHERE this data actually lives in Windows memory (e.g., "The user wants a hostname. Hostnames live in the PEB's environment variables, or in the SYSTEM registry hive.").
- Step 2 (Tool Mapping): Look at the Official Volatility 3 Plugin Catalog provided below. Find the plugin that interacts with the memory structure you identified in Step 1.
- Step 3 (Execution): Formulate a JSON proposal to run that specific plugin.

OFFICIAL VOLATILITY 3 WINDOWS PLUGIN CATALOG (YOUR ONLY TOOLS):
{CATALOG_PREVIEW}

RESPONSE FORMAT:
Always explain your technical reasoning (Step 1 and Step 2). If you need to run a plugin to gather evidence, end your response with a JSON object structured exactly like this:
{{
  "proposed_plugin": "windows.exact.plugin.name",
  "reason": "Why this plugin is required based on Windows Internals",
  "parameters": {{
    "pid": 1234
  }}
}}

If you already have enough information in the chat history to answer the question, answer the analyst directly without proposing a new plugin.
"""

def load_artifact(project_dir, filename):
    path = os.path.join(project_dir, filename)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return json.dumps(data, indent=2) if data else "[]"
        except Exception:
            return "[]"
    return "[]"

def build_correlation_prompt(project_dir):
    processes = load_artifact(project_dir, "filtered_processes.json")
    modules = load_artifact(project_dir, "filtered_modules.json")
    malfind = load_artifact(project_dir, "malfind.json")
    netscan = load_artifact(project_dir, "netscan.json")

    return f"""Initial triage artifacts from the target memory image:

=== SUSPICIOUS PROCESSES ===
{processes}

=== KERNEL MODULES ===
{modules}

=== INJECTIONS (MALFIND) ===
{malfind}

=== ACTIVE NETWORK CONNECTIONS ===
{netscan}

Identify the most critical anomalies and propose the next forensic step using the required JSON format.
"""

def _send_to_ollama(chat_history):
    payload = {
        "model": AI_MODEL,
        "messages": chat_history,
        "stream": False,
        "options": {
            "num_ctx": 32768,
            "temperature": 0.1
        }
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    response = urllib.request.urlopen(req)
    response_body = json.loads(response.read().decode('utf-8'))
    return response_body.get('message', {}).get('content', '')
