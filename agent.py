import subprocess
import json
from langchain_ollama import ChatOllama
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from vol_tool import run_volatility_plugin
from database import SessionLocal, Project, VolatilityCache

# 1. Initialize Qwen 2.5
llm = ChatOllama(model="qwen2.5:7b", temperature=0)

# 2. Initialize MemorySaver GLOBALLY so it persists across FastAPI requests
memory = MemorySaver()

# --- DISCOVERY TOOLS ---
def search_plugins() -> str:
    try:
        result = subprocess.run(["vol", "-h"], capture_output=True, text=True, check=True)
        if "Plugins:\n" not in result.stdout: return "Error: Could not find Plugins section."
        plugins_section = result.stdout.split("Plugins:\n")[1].split("The following plugins could not be loaded")[0]
        
        import re
        pattern = re.compile(r"^\s+([a-z_]+\.[a-zA-Z0-9_\.]+)\s+(.*?)(?=\n\s+[a-z_]+\.[a-zA-Z0-9_\.]+|\Z)", re.MULTILINE | re.DOTALL)
        matches = pattern.findall(plugins_section)
        
        formatted_output = "AVAILABLE VOLATILITY 3 PLUGINS:\n\n"
        for plugin_class, description in matches:
            callable_name = ".".join(plugin_class.split(".")[:2])
            clean_desc = re.sub(r'\s+', ' ', description.strip())
            if "(deprecated)" in clean_desc: continue
            formatted_output += f"- {callable_name}: {clean_desc}\n"
            
        return formatted_output
    except subprocess.CalledProcessError as e:
        return f"Error running 'vol -h': {e.stderr}"

def read_plugin_docs(plugin: str) -> str:
    try:
        result = subprocess.run(["vol", plugin, "-h"], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running 'vol {plugin} -h'. Error: {e.stderr}"

# --- EXECUTION & FILTERING TOOLS ---
def vol_executor(project_id: int, plugin: str, args: str = "") -> str:
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()
    
    # Strip hallucinated 'args' if the AI puts the plugin name in the args field
    if args == plugin: args = ""
    if plugin.startswith(args): args = ""
    
    raw_output = run_volatility_plugin(project_id, project.dump_path, plugin, args)
    json_str = raw_output.replace("[CACHED RESULT]\n", "").replace("[NEW RESULT]\n", "").strip()
    
    formatted_output = ""
    try:
        if "[" in json_str: json_str = json_str[json_str.find("["):]
        data = json.loads(json_str)
        for row in data:
            row.pop("__children", None) 
            formatted_output += " | ".join([f"{k}: {v}" for k, v in row.items()]) + "\n"
    except Exception:
        formatted_output = json_str

    if plugin in ["windows.info", "linux.info", "mac.info"]: return formatted_output
    if len(formatted_output) > 3000:
        return formatted_output[:3000] + f"\n\n...[DATA TRUNCATED: OUTPUT TOO LARGE. USE Filter_Cached_Output WITH plugin_command='{plugin} {args}'.]"
        
    return formatted_output

def filter_cached_output(project_id: int, plugin_command: str, search_term: str) -> str:
    db = SessionLocal()
    cached = db.query(VolatilityCache).filter_by(project_id=project_id, plugin_command=plugin_command.strip()).first()
    db.close()
    
    if not cached: return f"Error: No cached output found for '{plugin_command}'. You must run the plugin first."
    
    try:
        json_str = cached.output_json
        if "[" in json_str: json_str = json_str[json_str.find("["):]
        data = json.loads(json_str)
        filtered_results = []
        for row in data:
            if search_term.lower() in json.dumps(row).lower():
                row.pop("__children", None)
                filtered_results.append(row)
                
        if not filtered_results: return f"No matches found for '{search_term}'."
        
        flat_results = ""
        for row in filtered_results:
            flat_results += " | ".join([f"{k}: {v}" for k, v in row.items()]) + "\n"
            
        return flat_results
    except Exception as e:
        return f"Failed to filter JSON: {str(e)}"

# --- SCHEMAS ---
class PluginSearchSchema(BaseModel): query: str = Field(default="")
class PluginHelpSchema(BaseModel): plugin: str
class VolatilityToolSchema(BaseModel): 
    plugin: str
    args: str = Field(default="")
class FilterSchema(BaseModel):
    plugin_command: str
    search_term: str

# --- MAIN LOOP ---
def handle_forensics_query(project_id: int, user_query: str) -> str:
    tools = [
        StructuredTool.from_function(func=lambda query="": search_plugins(), name="Search_Plugins", description="List all Volatility plugins.", args_schema=PluginSearchSchema),
        StructuredTool.from_function(func=read_plugin_docs, name="Read_Plugin_Docs", description="Read the manual for a specific plugin to learn its arguments.", args_schema=PluginHelpSchema),
        StructuredTool.from_function(func=lambda plugin, args="": vol_executor(project_id, plugin, args), name="Run_Volatility_3", description="Execute a plugin.", args_schema=VolatilityToolSchema),
        StructuredTool.from_function(func=lambda plugin_command, search_term: filter_cached_output(project_id, plugin_command, search_term), name="Filter_Cached_Output", description="Searches the massive JSON output of a previously run plugin for specific keywords.", args_schema=FilterSchema)
    ]
    
    # 3. Create the agent with the GLOBAL memory
    agent_executor = create_react_agent(llm, tools, checkpointer=memory)
    
    system_prompt = """You are an autonomous Memory Forensics Investigator using Volatility 3.

METHODOLOGY:
1. HYPOTHESIZE: Think about where the artifact might live. Note the OS you are investigating based on previous context.
2. DISCOVER: Call 'Search_Plugins' to find a relevant tool.
3. READ DOCS: Call 'Read_Plugin_Docs' to understand the arguments required for that tool.
4. EXECUTE: Call 'Run_Volatility_3'.
5. FILTER: If 'Run_Volatility_3' tells you the data was truncated, DO NOT GUESS. You MUST use 'Filter_Cached_Output' to search the full data for the specific keyword.

VOLATILITY 3 RULES:
- Plugins must be called with their OS prefix (e.g., 'windows.info', NOT 'info').
"""

    try:
        config = {"configurable": {"thread_id": str(project_id)}, "recursion_limit": 30}
        
        # 4. Check if the thread already has history. If not, inject the system prompt.
        current_state = agent_executor.get_state(config)
        
        messages = []
        if not current_state.values.get("messages"):
            # Brand new conversation
            messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_query}]
        else:
            # Continuing conversation: Just send the user query, LangGraph remembers the rest!
            messages = [{"role": "user", "content": user_query}]
        
        print(f"\n--- [AGENT STARTING | Thread ID: {project_id}] ---")
        for step in agent_executor.stream({"messages": messages}, config=config, stream_mode="values"):
            last_msg = step["messages"][-1]
            if last_msg.type == "ai":
                if last_msg.tool_calls:
                    print(f"\n[AI Action] Calling: {last_msg.tool_calls[0]['name']} | Args: {last_msg.tool_calls[0]['args']}")
                elif last_msg.content:
                    print(f"\n[AI Thought]:\n{last_msg.content[:200]}")
            elif last_msg.type == "tool":
                print(f"[Tool Result from {last_msg.name}]: {last_msg.content[:200]}... [Truncated for UI]")
                
        print("\n--- [AGENT FINISHED] ---")
        return agent_executor.get_state(config).values["messages"][-1].content
    except Exception as e:
        return f"Error: {str(e)}"
