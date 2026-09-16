import os
import re
import json
import string
import platform
import streamlit as st
import pandas as pd

from core_triage import analyze_windows_dump, run_dynamic_plugin
from ai_copilot import build_correlation_prompt, _send_to_ollama, SYSTEM_PROMPT

# --- Page Setup & CSS Hacks ---
st.set_page_config(page_title="Captain-VolAI", layout="wide", page_icon="🧠")
st.markdown("""
    <style>
    h1, h2, h3 { color: #ff4b4b !important; }
    .stDataFrame { border: 1px solid #ff4b4b; border-radius: 5px; }
    [data-testid="stStatusWidget"] { visibility: hidden; height: 0%; }
    .stProgress > div > div > div > div { background-color: #ff4b4b; }
    div[data-testid="stFileUploader"] { border: 1px dashed #ff4b4b; border-radius: 8px; padding: 10px; }
    </style>
""", unsafe_allow_html=True)

PROJECTS_ROOT = os.path.join(os.getcwd(), "projects")
os.makedirs(PROJECTS_ROOT, exist_ok=True)

if "project_dir" not in st.session_state: st.session_state.project_dir = None
if "chat_history" not in st.session_state: st.session_state.chat_history = []
if "triage_done" not in st.session_state: st.session_state.triage_done = False
if "dump_target" not in st.session_state: st.session_state.dump_target = None

# Smart Initial Directory depending on OS
if "browser_current_dir" not in st.session_state:
    if os.name == 'nt':
        st.session_state.browser_current_dir = "C:\\"
    elif os.path.exists("/mnt/c"):
        st.session_state.browser_current_dir = "/mnt/c"
    else:
        st.session_state.browser_current_dir = os.path.expanduser("~")

def load_df(filename):
    if not st.session_state.project_dir:
        return pd.DataFrame([{"Status": "No active project"}])
    path = os.path.join(st.session_state.project_dir, filename)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return pd.DataFrame(data) if data else pd.DataFrame([{"Info": "Empty"}])
        except Exception as e:
            return pd.DataFrame([{"Error": str(e)}])
    return pd.DataFrame([{"Status": "Not Found"}])

# ==========================================
# SIDEBAR
# ==========================================
with st.sidebar:
    if os.path.exists("captain_volatilitAI_logo.png"):
        st.image("captain_volatilitAI_logo.png", use_container_width=True)
    st.header("📁 Projects")

    tab_new, tab_load = st.tabs(["New Project", "Load Project"])

    # --- TAB 1: NEW PROJECT ---
    with tab_new:
        proj_name = st.text_input("Project Name (e.g., Incident_01)")

        st.markdown("### 💾 Select Memory Dump")
        source_mode = st.radio("Source Location", ["Browse Server Disks", "Upload via Browser"])

        target_dump_path = None

        if source_mode == "Browse Server Disks":
            # 1. OS-Agnostic Root Drive Detection
            system_roots = []
            if os.name == 'nt':
                system_roots = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            else:
                if os.path.exists("/mnt/c"): system_roots.append("/mnt/c") # WSL
                system_roots.append("/") # Linux Root
                system_roots.append(os.path.expanduser("~")) # Linux Home
            
            st.caption("**Quick Jumps:**")
            cols = st.columns(len(system_roots))
            for i, root in enumerate(system_roots):
                if cols[i].button(f"📁 {root}", key=f"btn_{root}", use_container_width=True):
                    st.session_state.browser_current_dir = root
                    st.rerun()

            # 2. Interactive Server Browser
            st.code(st.session_state.browser_current_dir, language="bash")
            
            try:
                raw_entries = sorted(os.listdir(st.session_state.browser_current_dir))
            except PermissionError:
                st.error("Permission Denied.")
                raw_entries = []
            except Exception as e:
                st.error(f"Error accessing directory: {e}")
                raw_entries = []

            dirs = [d for d in raw_entries if os.path.isdir(os.path.join(st.session_state.browser_current_dir, d)) and not d.startswith(".")]
            dumps = [f for f in raw_entries if f.lower().endswith(('.dmp', '.raw', '.vmem', '.img', '.bin', '.mem', '.dd'))]

            selected_sub = st.selectbox("📂 Step into folder:", ["-- Stay Here --", "⬆️ .. (Up One Level)"] + dirs)
            if selected_sub == "⬆️ .. (Up One Level)":
                parent_dir = os.path.dirname(st.session_state.browser_current_dir)
                if parent_dir != st.session_state.browser_current_dir:
                    st.session_state.browser_current_dir = parent_dir
                    st.rerun()
            elif selected_sub != "-- Stay Here --":
                st.session_state.browser_current_dir = os.path.join(st.session_state.browser_current_dir, selected_sub)
                st.rerun()

            if dumps:
                selected_dump = st.selectbox("🎯 Target Dump File:", ["-- Choose a dump --"] + dumps)
                if selected_dump != "-- Choose a dump --":
                    target_dump_path = os.path.join(st.session_state.browser_current_dir, selected_dump)
                    st.success(f"Ready: {selected_dump}")
            else:
                st.caption("No supported memory dumps found in this folder.")

        else:
            # Browser Upload Mode
            uploaded_file = st.file_uploader("Select dump file", type=["dmp", "raw", "vmem", "img", "bin", "mem", "dd"])
            if uploaded_file and proj_name:
                temp_dir = os.path.join(PROJECTS_ROOT, proj_name)
                os.makedirs(temp_dir, exist_ok=True)
                dest = os.path.join(temp_dir, uploaded_file.name)
                if not os.path.exists(dest):
                    with st.spinner("Saving uploaded dump to project directory..."):
                        with open(dest, "wb") as f:
                            while chunk := uploaded_file.read(16 * 1024 * 1024):
                                f.write(chunk)
                target_dump_path = dest
                st.success(f"Uploaded: `{uploaded_file.name}`")

        st.markdown("---")
        if st.button("Create & Run Triage", type="primary", use_container_width=True):
            if not proj_name:
                st.error("Please provide a Project Name.")
            elif not target_dump_path or not os.path.exists(target_dump_path):
                st.error("Please pick a valid memory dump.")
            else:
                proj_path = os.path.join(PROJECTS_ROOT, proj_name)
                os.makedirs(proj_path, exist_ok=True)
                st.session_state.project_dir = proj_path
                st.session_state.dump_target = target_dump_path
                st.session_state.chat_history = []

                st.markdown("### ⚡ Analysis Execution")
                prog_bar = st.progress(0.0)
                status_text = st.empty()

                def update_progress(percent, text):
                    prog_bar.progress(percent)
                    status_text.caption(f"🚀 {text} ({int(percent * 100)}%)")

                try:
                    analyze_windows_dump(target_dump_path, proj_path, progress_cb=update_progress)
                    status_text.success("Triage Complete!")
                    st.session_state.triage_done = True
                    st.rerun()
                except Exception as e:
                    st.error(f"Fatal error during triage: {str(e)}")

    # --- TAB 2: LOAD EXISTING PROJECT ---
    with tab_load:
        existing = [d for d in os.listdir(PROJECTS_ROOT) if os.path.isdir(os.path.join(PROJECTS_ROOT, d))]
        if existing:
            selected_proj = st.selectbox("Select Project", existing)
            if st.button("Load Workspace", use_container_width=True):
                st.session_state.project_dir = os.path.join(PROJECTS_ROOT, selected_proj)
                st.session_state.triage_done = True
                st.session_state.chat_history = []
                st.rerun()

# ==========================================
# MAIN DASHBOARD
# ==========================================
if st.session_state.project_dir and st.session_state.triage_done:
    with st.expander("ℹ️ Target Image Information (windows.info)", expanded=False):
        st.dataframe(load_df("image_info.json"), use_container_width=True)

    col_data, col_chat = st.columns([1.5, 1])

    # --- LEFT COLUMN: ARTIFACTS & TAGS ---
    with col_data:
        st.header("📊 Forensics Artifacts")

        t1, t2, t3, t4, t_notes, t_dyn = st.tabs([
            "Processes", "Modules", "Injections", "Network", "🏷️ Tags & Notes", "⚡ Dynamic Plugins"
        ])

        with t1: st.dataframe(load_df("filtered_processes.json"), height=520, use_container_width=True)
        with t2: st.dataframe(load_df("filtered_modules.json"), height=520, use_container_width=True)
        with t3: st.dataframe(load_df("malfind.json"), height=520, use_container_width=True)
        with t4: st.dataframe(load_df("netscan.json"), height=520, use_container_width=True)

        with t_notes:
            notes_file = os.path.join(st.session_state.project_dir, "notes.json")
            notes_df = pd.read_json(notes_file) if os.path.exists(notes_file) else pd.DataFrame(columns=["Category", "Target", "Tag", "Note"])

            with st.form("add_tag_form"):
                c1, c2, c3 = st.columns(3)
                cat = c1.selectbox("Category", ["Process", "Module", "Injection", "Network"])
                target = c2.text_input("Target (e.g. PID 6316)")
                tag = c3.selectbox("Tag", ["🔴 Malicious", "🟡 Suspicious", "🟢 Legitimate", "🔎 Investigate"])
                note = st.text_input("Analyst Note")
                if st.form_submit_button("Add Note / Tag"):
                    new_row = pd.DataFrame([{"Category": cat, "Target": target, "Tag": tag, "Note": note}])
                    notes_df = pd.concat([notes_df, new_row], ignore_index=True)
                    notes_df.to_json(notes_file, orient="records")
                    st.rerun()

            edited_notes = st.data_editor(notes_df, num_rows="dynamic", use_container_width=True)
            if not edited_notes.equals(notes_df):
                edited_notes.to_json(notes_file, orient="records")

        with t_dyn:
            st.caption("Artifacts dynamically requested by Qwen will appear here.")
            dyn_files = [f for f in os.listdir(st.session_state.project_dir) if f.startswith("dynamic_")]
            if dyn_files:
                target_dyn = st.selectbox("Select Generated Plugin Output", dyn_files)
                dyn_df = load_df(target_dyn)

                search_q = st.text_input("🔍 Filter rows by keyword")
                if search_q:
                    dyn_df = dyn_df[dyn_df.apply(lambda row: row.astype(str).str.contains(search_q, case=False).any(), axis=1)]

                st.dataframe(dyn_df, use_container_width=True, height=450)
            else:
                st.info("No dynamic plugins executed yet.")

    # --- RIGHT COLUMN: AI COPILOT CHAT ---
    with col_chat:
        st.header("🤖 Qwen Copilot")

        if not st.session_state.chat_history:
            with st.spinner("Qwen is inspecting artifacts..."):
                initial_prompt = build_correlation_prompt(st.session_state.project_dir)
                st.session_state.chat_history = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": initial_prompt}
                ]
                ai_response = _send_to_ollama(st.session_state.chat_history)
                st.session_state.chat_history.append({"role": "assistant", "content": ai_response})

        chat_container = st.container(height=550)
        with chat_container:
            for msg in st.session_state.chat_history:
                if msg["role"] == "assistant":
                    with st.chat_message("AI", avatar="🤖"): st.markdown(msg["content"])
                elif msg["role"] == "user" and not msg["content"].startswith("Analyze these cleaned"):
                    with st.chat_message("Analyst", avatar="🕵️"): st.markdown(msg["content"])

        if user_prompt := st.chat_input("Ask Qwen to investigate a PID..."):
            st.session_state.chat_history.append({"role": "user", "content": user_prompt})
            with chat_container:
                with st.chat_message("Analyst", avatar="🕵️"): st.markdown(user_prompt)

                with st.chat_message("AI", avatar="🤖"):
                    with st.spinner("Thinking..."):
                        response = _send_to_ollama(st.session_state.chat_history)
                        plugin_match = re.search(r'\[RUN_PLUGIN:\s*([^\|\]]+)(?:\|\s*([^\]]+))?\]', response)

                        st.markdown(response)
                        st.session_state.chat_history.append({"role": "assistant", "content": response})

                        if plugin_match and st.session_state.dump_target:
                            plugin_name = plugin_match.group(1).strip()
                            args_str = plugin_match.group(2)

                            kwargs = {}
                            if args_str:
                                for pair in args_str.split(','):
                                    if '=' in pair:
                                        k, v = pair.split('=')
                                        kwargs[k.strip()] = v.strip()

                            st.info(f"⚙️ AI requested Volatility plugin: `{plugin_name}`")
                            with st.spinner(f"Running {plugin_name}..."):
                                msg, raw_data = run_dynamic_plugin(st.session_state.dump_target, st.session_state.project_dir, plugin_name, kwargs)
                                st.success(msg)

                                truncation_limit = 30
                                truncated_data = raw_data[:truncation_limit]
                                feedback = (
                                    f"SYSTEM NOTIFICATION: Plugin {plugin_name} finished. "
                                    f"Showing top {truncation_limit} results:\n"
                                    f"{json.dumps(truncated_data, indent=2)}\n\n"
                                    f"Synthesize your findings for the analyst."
                                )
                                st.session_state.chat_history.append({"role": "user", "content": feedback})
                                st.rerun()
else:
    st.title("Welcome to Captain-VolAI")
    st.info("👈 Use the sidebar to click and select a memory dump to start.")
