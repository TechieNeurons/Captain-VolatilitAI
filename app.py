import streamlit as st
import subprocess
import json
import pandas as pd
import requests
import os

# --- Configuration ---
st.set_page_config(page_title="DFIR Copilot", layout="wide")
OLLAMA_URL = "http://ollama:11434/api/generate"
MODEL_NAME = "forensic-copilot" # Using the custom Modelfile

# --- State Management (The Ledger) ---
if "investigation_ledger" not in st.session_state:
    st.session_state.investigation_ledger = {
        "os_profile": None,
        "merged_df": pd.DataFrame(),
        "process_tree": "",
        "chat_history": []
    }

def run_volatility(dump_path, plugin, output_dir):
    """Runs a Volatility 3 plugin."""
    cmd = ["vol", "-f", dump_path, "-r", "json", plugin]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr
    try:
        data = json.loads(result.stdout)
        with open(os.path.join(output_dir, f"{plugin}.json"), "w") as f:
            json.dump(data, f, indent=4)
        return pd.DataFrame(data), None
    except json.JSONDecodeError:
        return None, f"Failed to parse JSON. Raw output: {result.stdout}"

def ask_ai(prompt):
    """Queries the custom Ollama model."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    try:
        return requests.post(OLLAMA_URL, json=payload).json().get("response", "Error getting response.")
    except Exception as e:
        return f"API Error: {str(e)}"

def build_process_tree(df):
    """Builds an indented process tree highlighting DKOM."""
    if df.empty:
        return "No data to build tree."
        
    tree_lines = []
    pid_map = {}
    
    # Store process metadata
    for _, row in df.iterrows():
        pid_map[row['PID']] = {
            'name': row.get('ImageFileName', 'Unknown'),
            'ppid': row.get('PPID', None),
            'cmd': str(row.get('ProcessArgs', '-')),
            # Check for DKOM safely handling string 'N/A' or NaNs
            'dkom': (str(row.get('pslist')) == 'False' and str(row.get('psscan')) == 'True')
        }
        
    def render_branch(pid, depth=0):
        info = pid_map.get(pid)
        if not info:
            return
        flag = " [!] (DKOM / HIDDEN)" if info['dkom'] else ""
        indent = "  " * depth + "└─ " if depth > 0 else ""
        tree_lines.append(f"{indent}{info['name']} (PID: {pid} | PPID: {info['ppid']}){flag}")
        
        # Find children
        children = [p for p, data in pid_map.items() if data['ppid'] == pid and p != pid]
        for child in children:
            render_branch(child, depth + 1)

    # Find root processes (PPID not in list or System process)
    roots = [p for p, data in pid_map.items() if data['ppid'] not in pid_map or p == 4]
    for root in set(roots):
        render_branch(root, 0)
        
    return "\n".join(tree_lines)

# --- UI Sidebar ---
with st.sidebar:
    st.title("⚙️ DFIR Copilot Setup")
    project_name = st.text_input("Project Name", "Investigation_01")
    dump_path = st.text_input("Path to Memory Dump", "/dumps/malware_analyst_dumpit_dump.dmp")
    
    if st.button("1. Ingest Memory Dump"):
        output_dir = f"./projects/{project_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        with st.spinner("Profiling OS (windows.info)..."):
            info_df, err = run_volatility(dump_path, "windows.info.Info", output_dir)
            if err or info_df is None or info_df.empty:
                st.error("Error running windows.info")
                st.code(err)
            else:
                # Extract basic OS info for the ledger
                try:
                    is64 = info_df[info_df['Variable'] == 'Is64Bit']['Value'].values[0]
                    maj_min = info_df[info_df['Variable'] == 'Major/Minor']['Value'].values[0]
                    sys_time = info_df[info_df['Variable'] == 'SystemTime']['Value'].values[0]
                    st.session_state.investigation_ledger['os_profile'] = f"Windows NT {maj_min} (64-bit: {is64}) | Dump Time: {sys_time}"
                    st.success("OS Profiled.")
                except:
                    st.session_state.investigation_ledger['os_profile'] = "Windows Profile Extracted (Details in raw JSON)"
                    st.success("OS Profiled.")

        with st.spinner("Extracting Processes (pslist, psscan, psxview, cmdline)..."):
            plugins = ["windows.pslist.PsList", "windows.psscan.PsScan", "windows.psxview.PsXView", "windows.cmdline.CmdLine"]
            dataframes = {}
            for plugin in plugins:
                df, _ = run_volatility(dump_path, plugin, output_dir)
                if df is not None and 'PID' in df.columns:
                    dataframes[plugin] = df

            # --- Data Fusion ---
            all_pids = set()
            for df in dataframes.values():
                all_pids.update(df['PID'].dropna().tolist())
            merged_df = pd.DataFrame({'PID': list(all_pids)})
            
            core_cols = ['PID', 'PPID', 'ImageFileName', 'CreateTime', 'ExitTime']
            core_info = pd.DataFrame()
            if 'windows.psscan.PsScan' in dataframes:
                avail = [c for c in core_cols if c in dataframes['windows.psscan.PsScan'].columns]
                core_info = pd.concat([core_info, dataframes['windows.psscan.PsScan'][avail]])
            if 'windows.pslist.PsList' in dataframes:
                avail = [c for c in core_cols if c in dataframes['windows.pslist.PsList'].columns]
                core_info = pd.concat([core_info, dataframes['windows.pslist.PsList'][avail]])
            
            core_info = core_info.drop_duplicates(subset=['PID'], keep='first')
            merged_df = merged_df.merge(core_info, on='PID', how='left')

            if 'windows.psxview.PsXView' in dataframes:
                psx_cols = ['PID'] + [c for c in ['pslist', 'psscan'] if c in dataframes['windows.psxview.PsXView'].columns]
                merged_df = merged_df.merge(dataframes['windows.psxview.PsXView'][psx_cols], on='PID', how='left')

            if 'windows.cmdline.CmdLine' in dataframes:
                cmd_df = dataframes['windows.cmdline.CmdLine'].copy()
                if 'Args' in cmd_df.columns: cmd_df = cmd_df.rename(columns={'Args': 'ProcessArgs'})
                if 'ProcessArgs' in cmd_df.columns:
                    merged_df = merged_df.merge(cmd_df[['PID', 'ProcessArgs']], on='PID', how='left')

            merged_df.fillna("N/A", inplace=True)
            
            # Save to state
            st.session_state.investigation_ledger['merged_df'] = merged_df
            st.session_state.investigation_ledger['process_tree'] = build_process_tree(merged_df)
            
            # Initial AI prompt upon ingestion
            context_prompt = f"""
            Initial Analysis Phase.
            OS: {st.session_state.investigation_ledger['os_profile']}
            
            Review this Process Tree. Look for DKOM flags or parent-child anomalies (e.g. svchost not spawned by services).
            List the most critical findings.
            
            TREE:
            {st.session_state.investigation_ledger['process_tree']}
            """
            st.session_state.investigation_ledger['chat_history'].append({"role": "system", "content": "Ingested memory dump. Performing initial triage..."})
            initial_response = ask_ai(context_prompt)
            st.session_state.investigation_ledger['chat_history'].append({"role": "ai", "content": initial_response})
            st.rerun()

# --- Main UI Layout ---
col_data, col_chat = st.columns([1, 1], gap="large")

with col_data:
    st.header("🔍 Process Hierarchy")
    if st.session_state.investigation_ledger['process_tree']:
        st.text_area("Process Tree (Computed by Python)", st.session_state.investigation_ledger['process_tree'], height=600)
    else:
        st.info("Awaiting Memory Dump Ingestion...")

    st.header("📊 Raw Merged Data")
    if not st.session_state.investigation_ledger['merged_df'].empty:
        st.dataframe(st.session_state.investigation_ledger['merged_df'], use_container_width=True)

with col_chat:
    st.header("🤖 DFIR Copilot Chat")
    
    # Display Chat History
    for msg in st.session_state.investigation_ledger['chat_history']:
        if msg["role"] == "user":
            st.markdown(f"**You:** {msg['content']}")
        elif msg["role"] == "ai":
            st.markdown(f"**KERNEL-AI:**\n{msg['content']}")
            st.divider()
        else:
            st.caption(msg['content'])

    # Chat Input Box
    user_query = st.chat_input("Ask the AI to analyze a specific PID or relationship...")
    
    if user_query:
        # Add to history
        st.session_state.investigation_ledger['chat_history'].append({"role": "user", "content": user_query})
        
        # Build prompt with current context
        context = f"OS: {st.session_state.investigation_ledger['os_profile']}\n"
        context += f"PROCESS TREE:\n{st.session_state.investigation_ledger['process_tree']}\n"
        
        full_prompt = f"Given this context:\n{context}\n\nAnalyst Query: {user_query}"
        
        with st.spinner("Analyzing..."):
            response = ask_ai(full_prompt)
            st.session_state.investigation_ledger['chat_history'].append({"role": "ai", "content": response})
            st.rerun()
