# Captain-VolatilitAI 🧠🔍

![Captain-VolatilitAI Logo](captain_volatilitAI_logo.png)

**Captain-VolatilitAI** (**Captain-VolAI**) is a memory forensics AI assistant

It leverages **Volatility 3** for lightning-fast, multiprocessing memory triage, applies strict **Windows Internals heuristics** to filter out noise, and drops the cleaned artifacts into a **Local AI Copilot (Ollama + Qwen)** for offline, privacy-safe forensics correlation.

## Features

* **Multiprocessing Triage:** Executes 14 highly targeted Volatility 3 plugins (Process, Network, and Kernel/Rootkit) in parallel using `ProcessPoolExecutor`.
* **Heuristic Correlation Engine:** Merges cross-plugin outputs (e.g., `pslist` vs `psscan`, `modules` vs `modscan`) to automatically flag Direct Kernel Object Manipulation (DKOM), unlinked processes, and hidden rootkit drivers.
* **Smart Noise Filtering:** Uses established Windows Core Process baselines to drop legitimate OS execution noise without accidentally deleting masqueraded malware.
* **Agentic Local AI Copilot:** Uses Ollama and `qwen2.5:7b`, or 14b if enough power, to ingest all cleaned JSON artifacts, correlate malicious behavior step-by-step, and generate a comprehensive forensics report—all completely offline.

## Prerequisites

1. **Python 3.x**
2. **Volatility 3:** 
```bash
# need volatility3 installed via pip to import it as package
pip install volatility3

# Installing ollama
curl -fsSL https://ollama.com/install.sh | sh

# launching qwen once to have it running in the background
ollama run qwen2.5:7b
```

## Usage

1. Standard run (Triage + clean + AI Copilot)

Extracts memory artifacts, runs the heuristic cleaner, and automatically drops you into AI

```bash
python main.py /path/to/memory.dmp
```

2. Triage & Clean Only (No AI)

Generates the raw and filtered_*.json files for manual review, bypassing the LLM.

```Bash
python main.py /path/to/memory.dmp --triage-only
```

3. AI Copilot Only

If you have already extracted and cleaned the JSON artifacts in your current directory, you can jump straight back into the AI Copilot to ask questions.

```Bash
python main.py --skip-triage
```

## Project Structure

- `main.py`: The central command-line interface and orchestrator.
- `core_triage.py`: Handles the Volatility 3 multiprocessing execution and the heuristic JSON cleaning engine.
- `ai_copilot.py`: Manages the agentic AI workflow, constructs the massive prompt context, and interfaces with the local Ollama API.

## Privacy & OPSEC

Because memory dumps contain highly sensitive data (passwords, proprietary code, PII), Captain-VolatilitAI is designed to be 100% offline. The AI copilot runs entirely on your local hardware via Ollama.

## Little example
Analysing a simple dump with a malware in running, launching the script with only the dump as an argument:
```bash
$ python main.py /mnt/c/Users/riend/Downloads/BOOK_MEM_SAMPLE/malware_analyst_dumpit_dump.dmp

=========================================================================
   ____             _        _             __     __    _      _    ___
  / ___|__ _ _ __  | |_ __ _(_)_ __        \ \   / /__ | |    / \  |_ _|
 | |   / _` | '_ \ | __/ _` | | '_ \ _____  \ \ / / _ \| |   / _ \  | |
 | |__| (_| | |_) || || (_| | | | | |_____|  \ V / (_) | |__/ ___ \ | |
  \____\__,_| .__/  \__\__,_|_|_| |_|         \_/ \___/|___/_/   \_\___|
            |_|
                  Memory Forensics & DFIR Copilot
=========================================================================

[*] Target Image: /mnt/c/Users/riend/Downloads/BOOK_MEM_SAMPLE/malware_analyst_dumpit_dump.dmp
```

First the script is finding the correct ISF to use, the script give the output of imageinfo:
```bash
[+] Windows Memory Dump Successfully Identified and ISF Loaded!
------------------------------------------------------------
Kernel Base = 0xf80648a00000
DTB = 0x1ae000
Symbols = file:///home/tcherenkoveffect/.local/lib/python3.14/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/CF32DE2E4A334C7C06FB63FCB6FAFB5C-1.json.xz
Is64Bit = True
IsPAE = False
layer_name = 0 WindowsIntel32e
memory_layer = 1 WindowsCrashDump64Layer
base_layer = 2 FileLayer
KdVersionBlock = 0xf806496099a0
Major/Minor = 15.22621
MachineType = 34404
KeNumberProcessors = 4
SystemTime = 2026-03-18 21:20:35+00:00
NtSystemRoot = C:\Windows
NtProductType = NtProductWinNt
NtMajorVersion = 10
NtMinorVersion = 0
PE MajorOperatingSystemVersion = 10
PE MinorOperatingSystemVersion = 0
PE Machine = 34404
PE TimeDateStamp = Tue Jun 17 09:32:46 2036
------------------------------------------------------------
```

Then multiple plugins are launched (multi tasked) to get as much basic info as possible:
```bash
[*] Starting Multiprocessing Triage Plugins...
[*] [Worker] Started scanning: psxview
[*] [Worker] Started scanning: psscan
[*] [Worker] Started scanning: cmdline
[*] [Worker] Started scanning: pslist
[*] [Worker] Started scanning: cmdscan
[+] [Worker] Successfully finished pslist -> pslist.json
[*] [Worker] Started scanning: netscan
[*] [Worker] Started scanning: modules
[*] [Worker] Started scanning: modscan
[*] [Worker] Started scanning: unloadedmodules
[+] [Worker] Successfully finished psscan -> psscan.json
[*] [Worker] Started scanning: callbacks
[*] [Worker] Started scanning: malfind
[*] [Worker] Started scanning: ldrmodules
[*] [Worker] Started scanning: hollowprocesses
[*] [Worker] Started scanning: pebmasquerade
[+] [Worker] Successfully finished psxview -> psxview.json
[+] [Worker] Successfully finished cmdline -> cmdline.json
[+] [Worker] Successfully finished cmdscan -> cmdscan.json
[+] [Worker] Successfully finished netscan -> netscan.json
[+] [Worker] Successfully finished modules -> modules.json
[+] [Worker] Successfully finished modscan -> modscan.json
[+] [Worker] Successfully finished unloadedmodules -> unloadedmodules.json
[+] [Worker] Successfully finished callbacks -> callbacks.json
[+] [Worker] Successfully finished malfind -> malfind.json
[+] [Worker] Successfully finished ldrmodules -> ldrmodules.json
[+] [Worker] Successfully finished hollowprocesses -> hollowprocesses.json
[+] [Worker] Successfully finished pebmasquerade -> pebmasquerade.json

[+] Triage completed. Check the local directory for JSON files.
```

Then the script clean a bit the results, we don't want to give known good processes to the AI for example:
```bash
[+] Cleaning before ingesting.

============================================================
[*] STARTING CORRELATION & HEURISTIC CLEANING PIPELINE
============================================================
[*] Merging pslist, psscan, and cmdline...
[*] Filtering out legitimate Windows processes...
[+] Process analysis complete:
    - Total Merged: 207
    - Legitimate Filtered: 53
    - Suspicious / Anomalies Retained: 154 -> saved to filtered_processes.json

[*] Merging and filtering kernel modules (modules + modscan)...
[+] Kernel Module analysis complete:
    - Total Merged: 204
    - Legitimate Filtered: 179
    - Suspicious / Unlinked Modules Retained: 25 -> saved to filtered_modules.json
============================================================

[+] Memory extraction and correlation completed successfully.
```

Before launching you inside the AI prompt the script ask you if you are ready to do so, after quite some time the AI will give a first report:
```bash
[?] Ready to engage the DFIR AI Copilot? (Y/n): y

============================================================
[*] INITIALIZING QWEN DFIR COPILOT...
============================================================

[*] Qwen 2.5 is analyzing and correlating artifacts (This may take a minute or two on local hardware)...
```

The AI give his report about what could be malicious and why:
```bash
================================================================================
                        AI CORRELATION REPORT
================================================================================
### Step 1: Process Analysis

#### Suspect Processes:
1. **PID: 12852 - InstallUtil.exe**
   - **Parent Process:** Not explicitly listed, but could be svchost.exe or another system process.
   - **Execution Flags:** PAGE_EXECUTE_READWRITE, which is common for legitimate processes.
   - **Command-Line Path:** Not provided, but the process name is common for installation utilities.
   - **Network Connections:** No suspicious connections, but it has a large number of UDP and TCP connections.
   - **Modules:** No suspicious modules identified.

2. **PID: 6160 - InstallUtil.exe**
   - **Parent Process:** Not explicitly listed, but could be svchost.exe or another system process.
   - **Execution Flags:** PAGE_EXECUTE_READWRITE, which is common for legitimate processes.
   - **Command-Line Path:** Not provided, but the process name is common for installation utilities.
   - **Network Connections:** No suspicious connections, but it has a large number of UDP and TCP connections.
   - **Modules:** No suspicious modules identified.

3. **PID: 10352 - RegSvcs.exe**
   - **Parent Process:** svchost.exe
   - **Execution Flags:** PAGE_EXECUTE_READWRITE, which is common for legitimate processes.
   - **Command-Line Path:** Not provided, but the process name is common for system services.
   - **Network Connections:** No suspicious connections, but it has a large number of UDP and TCP connections.
   - **Modules:** No suspicious modules identified.

4. **PID: 6316 - svchost.exe**
   - **Parent Process:** Not explicitly listed, but could be svchost.exe or another system process.
   - **Execution Flags:** PAGE_EXECUTE_READWRITE, which is common for legitimate processes.
   - **Command-Line Path:** Not provided, but the process name is common for system services.
   - **Network Connections:** No suspicious connections, but it has a large number of UDP and TCP connections.
   - **Modules:** No suspicious modules identified.

5. **PID: 1688 - MsMpEng.exe**
   - **Parent Process:** svchost.exe
   - **Execution Flags:** PAGE_EXECUTE_READWRITE, which is common for legitimate processes.
   - **Command-Line Path:** Not provided, but the process name is common for system services.
   - **Network Connections:** No suspicious connections, but it has a large number of UDP and TCP connections.
   - **Modules:** No suspicious modules identified.

### Step 2: Cross-Reference

#### Malfind Analysis:
- **PID: 12852 - InstallUtil.exe**
  - **Memory Sections:** No suspicious injected memory sections.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Hexdump:** No suspicious hexdump patterns.

- **PID: 6160 - InstallUtil.exe**
  - **Memory Sections:** No suspicious injected memory sections.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Hexdump:** No suspicious hexdump patterns.

- **PID: 10352 - RegSvcs.exe**
  - **Memory Sections:** No suspicious injected memory sections.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Hexdump:** No suspicious hexdump patterns.

- **PID: 6316 - svchost.exe**
  - **Memory Sections:** No suspicious injected memory sections.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Hexdump:** No suspicious hexdump patterns.

- **PID: 1688 - MsMpEng.exe**
  - **Memory Sections:** No suspicious injected memory sections.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Hexdump:** No suspicious hexdump patterns.

#### Network Connections:
- **PID: 12852 - InstallUtil.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **State:** Most connections are in a "CLOSED" state, which is normal for many legitimate processes.

- **PID: 6160 - InstallUtil.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **State:** Most connections are in a "CLOSED" state, which is normal for many legitimate processes.

- **PID: 10352 - RegSvcs.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **State:** Most connections are in a "CLOSED" state, which is normal for many legitimate processes.

- **PID: 6316 - svchost.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **State:** Most connections are in a "CLOSED" state, which is normal for many legitimate processes.

- **PID: 1688 - MsMpEng.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **State:** Most connections are in a "CLOSED" state, which is normal for many legitimate processes.

#### Filtered Modules:
- **PID: 12852 - InstallUtil.exe**
  - **Modules:** No suspicious modules identified.

- **PID: 6160 - InstallUtil.exe**
  - **Modules:** No suspicious modules identified.

- **PID: 10352 - RegSvcs.exe**
  - **Modules:** No suspicious modules identified.

- **PID: 6316 - svchost.exe**
  - **Modules:** No suspicious modules identified.

- **PID: 1688 - MsMpEng.exe**
  - **Modules:** No suspicious modules identified.

### Step 3: Correlation Report

#### Suspect PID/Activity:
- **PID: 12852 - InstallUtil.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **Modules:** No suspicious modules identified.
  - **Hexdump:** No suspicious hexdump patterns.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Conclusion:** This process appears to be a legitimate installation utility, but the large number of network connections could indicate it is communicating with a legitimate server. However, the sheer volume of connections could be a sign of a botnet or other malicious activity.

- **PID: 6160 - InstallUtil.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **Modules:** No suspicious modules identified.
  - **Hexdump:** No suspicious hexdump patterns.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Conclusion:** This process appears to be a legitimate installation utility, but the large number of network connections could indicate it is communicating with a legitimate server. However, the sheer volume of connections could be a sign of a botnet or other malicious activity.

- **PID: 10352 - RegSvcs.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **Modules:** No suspicious modules identified.
  - **Hexdump:** No suspicious hexdump patterns.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Conclusion:** This process appears to be a legitimate system service, but the large number of network connections could indicate it is communicating with a legitimate server. However, the sheer volume of connections could be a sign of a botnet or other malicious activity.

- **PID: 6316 - svchost.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **Modules:** No suspicious modules identified.
  - **Hexdump:** No suspicious hexdump patterns.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Conclusion:** This process appears to be a legitimate system service, but the large number of network connections could indicate it is communicating with a legitimate server. However, the sheer volume of connections could be a sign of a botnet or other malicious activity.

- **PID: 1688 - MsMpEng.exe**
  - **Network Connections:** Multiple connections to various IP addresses, but no known malicious IPs.
  - **Modules:** No suspicious modules identified.
  - **Hexdump:** No suspicious hexdump patterns.
  - **Disassembly:** No suspicious disassembly patterns.
  - **Conclusion:** This process appears to be a legitimate system service, but the large number of network connections could indicate it is communicating with a legitimate server. However, the sheer volume of connections could be a sign of a botnet or other malicious activity.

### Step 4: Next Steps

Based on the analysis, the following steps are recommended:

1. **Further Network Analysis:**
   - Perform a deeper network analysis to identify any known malicious IPs or domains that the processes might be communicating with.
   - Use tools like Wireshark to capture and analyze network traffic in real-time.

2. **Process Monitoring:**
   - Continuously monitor the processes for any unusual behavior, such as unexpected network connections or changes in memory usage.
   - Use tools like Process Explorer to monitor process activity in real-time.

3. **File Integrity Checks:**
   - Perform file integrity checks on the processes to ensure they have not been modified or replaced with malicious binaries.
   - Use tools like FileHash to verify the integrity of the processes.

4. **User Interaction:**
   - Ask the user if they have recently installed any software or if they have any knowledge of the processes.
   - Provide the user with a detailed report and ask for their input on the next steps.

5. **Advanced Analysis:**
   - If the user confirms that the processes are not legitimate, perform a more advanced analysis using tools like Volatility or Mimikatz to extract more detailed information about the processes.

### Final Report

Based on the analysis, the processes identified (12852, 6160, 10352, 6316, 1688) appear to be legitimate system processes, but the large number of network connections could indicate a potential botnet or other malicious activity. Further investigation is recommended to confirm the legitimacy of the processes and to identify any potential malicious behavior.

What specific aspect would you like to dive into next?
================================================================================
```

After giving his finding you drop inside the prompt and you can talk with him:
```bash
[*] Copilot is standing by. Type 'exit' to end the session.

[Analyst] >
```