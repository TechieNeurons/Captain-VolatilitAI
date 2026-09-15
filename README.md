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
