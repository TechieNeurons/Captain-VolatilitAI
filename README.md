# Captain-VolatilitAI: AI Memory Forensics Assistant

An AI-driven assistant for memory forensics using Volatility 3. It utilizes a local LLM (via Ollama) to reason through analyst requests, map them to Volatility plugins, execute them, and cache the JSON output to preserve context limits and save processing time.
Prerequisites

    Python 3.12: Required for compatibility with modern binary wheels.

    Volatility 3: Must be accessible via your command line (the vol command must work) with appropriate symbol tables.

    Ollama: Running locally with a tool-capable model (Llama 3.1 recommended).

Installation

1. Install Python 3.12 and create a virtual environment:
Bash

sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv build-essential

python3.12 -m venv venv
source venv/bin/activate

2. Install dependencies:
Bash

pip install --upgrade pip
pip install -r requirements.txt

Running the Application

    Ensure Ollama is running and the model is downloaded: ollama run llama3.1

    Start the FastAPI server from within your activated virtual environment:

Bash

uvicorn main:app --reload

    Access the interactive API interface at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
