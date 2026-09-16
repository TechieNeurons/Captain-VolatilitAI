import os
import json
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/chat"
AI_MODEL = "qwen2.5:7b" 

SYSTEM_PROMPT = """You are an elite Incident Response (DFIR) Copilot.
You possess deep knowledge of Windows Internals, Core Processes, and rootkits.

If you require deeper evidence to prove a hypothesis (like viewing a process's DLLs, handles, or privileges), you have the ability to execute Volatility 3 plugins on the fly. 
To do this, reply with the EXACT following syntax on a new line:
[RUN_PLUGIN: <plugin_name> | <arg_key>=<arg_value>]

Example to list DLLs for PID 6316:
[RUN_PLUGIN: windows.dlllist.DllList | pid=6316]

Example to check privileges for PID 824:
[RUN_PLUGIN: windows.privileges.Privs | pid=824]

The system will intercept this, run the command, and hand you the JSON results in the next prompt.
"""

def load_artifact(project_dir, filename):
    path = os.path.join(project_dir, filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                return json.dumps(data, indent=2) if data else "[]"
            except json.JSONDecodeError:
                return "[]"
    return "[]"

def build_correlation_prompt(project_dir):
    processes = load_artifact(project_dir, "filtered_processes.json")
    modules = load_artifact(project_dir, "filtered_modules.json")
    malfind = load_artifact(project_dir, "malfind.json")
    netscan = load_artifact(project_dir, "netscan.json")

    return f"""Analyze these cleaned artifacts from a compromised memory dump.

PROCESSES: {processes}
MODULES: {modules}
INJECTIONS: {malfind}
NETWORK: {netscan}

1. Identify suspect PIDs based on abnormal parent-child relationships or missing flags.
2. Cross-reference them with Injections, Network, and Modules.
3. If you are confident it is malware, explain why. If you need more data, use the [RUN_PLUGIN: ...] command to request specific details.
"""

def _send_to_ollama(chat_history):
    payload = {
        "model": AI_MODEL,
        "messages": chat_history,
        "stream": False,
        "options": {
            "num_ctx": 32768, 
            "temperature": 0.2 
        }
    }
    req = urllib.request.Request(
        OLLAMA_URL, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'}
    )
    response = urllib.request.urlopen(req)
    response_body = json.loads(response.read().decode('utf-8'))
    return response_body.get('message', {}).get('content', '')
