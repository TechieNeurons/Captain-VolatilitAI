<p align="center">
  <img src="captain_volatilitAI_logo.png" alt="Captain VolatilitAI Logo" width="300">
</p>

# Captain-VolatilitAI

Captain VolatilitAI is the memory forensics superhero we all need ! This superhero is using multi thread execution to automate basic memory forensics triage phase.

This script is executing all these plugin:
- "pslist"
- "psscan"
- "psxview"
- "cmdline"
- "cmdscan"
- "netscan"
- "modules"
- "modscan"
- "malfind"
The output of each plugin are written to a .json file.

## Requirements
Need to install volatility3 python library:
```bash
pip install volatility3
```

## How to launch
```bash
python volatilitai.py memory.dump
```
