import subprocess
from langchain_ollama import ChatOllama
from langchain_core.tools import StructuredTool, Tool
from pydantic import BaseModel, Field
from langgraph.prebuilt import create_react_agent
from vol_tool import run_volatility_plugin
from database import SessionLocal, Project

# Initialize Qwen 2.5
llm = ChatOllama(model="qwen2.5:7b", temperature=0)

# --- NEW DISCOVERY TOOLS (No caching needed for help menus) ---

def search_plugins() -> str:
    """Returns the main Volatility 3 help menu, listing all available plugins."""
    try:
        result = subprocess.run(["vol", "-h"], capture_output=True, text=True, check=True)
        # The output is long, but Qwen 2.5 has plenty of context window for it
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running 'vol -h': {e.stderr}"

def read_plugin_docs(plugin: str) -> str:
    """Returns the specific help menu and arguments for a single plugin."""
    try:
        result = subprocess.run(["vol", plugin, "-h"], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running 'vol {plugin} -h'. Make sure the plugin name is correct. Error: {e.stderr}"

# --- SCHEMAS ---

class PluginHelpSchema(BaseModel):
    plugin: str = Field(description="The exact name of the plugin to investigate (e.g., 'windows.info').")

class VolatilityToolSchema(BaseModel):
    plugin: str = Field(description="The exact name of the Volatility 3 plugin.")
    args: str = Field(default="", description="Optional arguments (e.g., '--key \"ControlSet001\\...\"').")

# --- MAIN AGENT LOOP ---

def handle_forensics_query(project_id: int, user_query: str) -> str:
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()
    
    if not project:
        return "Error: Project not found."

    def vol_executor(plugin: str, args: str = "") -> str:
        return run_volatility_plugin(project_id, project.dump_path, plugin, args)

    # 1. Tool to list all plugins
    tool_search_plugins = Tool(
        name="Search_Plugins",
        func=lambda _: search_plugins(), # Ignores input, just runs vol -h
        description="Call this to see a list of ALL available Volatility 3 plugins and their short descriptions. Use this if you don't know which plugin to use."
    )

    # 2. Tool to read specific plugin documentation
    tool_read_docs = StructuredTool.from_function(
        func=read_plugin_docs,
        name="Read_Plugin_Docs",
        description="Call this to read the official manual for a specific plugin. It reveals the exact arguments required. ALWAYS use this before executing a plugin you aren't familiar with.",
        args_schema=PluginHelpSchema,
    )

    # 3. Tool to execute
    tool_execute = StructuredTool.from_function(
        func=vol_executor,
        name="Run_Volatility_3",
        description="Execute a Volatility 3 plugin against the memory dump. Returns JSON output.",
        args_schema=VolatilityToolSchema,
    )
    
    tools = [tool_search_plugins, tool_read_docs, tool_execute]
    agent_executor = create_react_agent(llm, tools)
    
    # 4. Workflow Prompt (No cheat codes, just forensic methodology)
    system_prompt = """You are an elite Memory Forensics AI Assistant.
Your goal is to answer the user's question by actively investigating the memory dump using Volatility 3.

YOUR INVESTIGATION WORKFLOW:
1. HYPOTHESIZE: Think about where the requested artifact (e.g., hostname, malware, network connections) lives in an OS (RAM, Registry, Network stack).
2. DISCOVER: If you don't know the exact Volatility 3 plugin to use, call 'Search_Plugins' to read the global list of plugins.
3. READ THE DOCS: Once you identify a likely plugin (e.g., 'windows.registry.printkey'), call 'Read_Plugin_Docs' with that plugin name to learn its exact arguments and syntax.
4. EXECUTE: Call 'Run_Volatility_3' with the correct plugin and arguments.
5. ITERATE: If a plugin fails or doesn't return the data you need, re-evaluate, read the docs for a different plugin, and try again.
6. SYNTHESIZE: Once you have the data, provide a clear, professional answer to the user based on the tool output. Do not hallucinate data.
"""

    try:
        response = agent_executor.invoke({
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_query}
            ]
        })
        return response["messages"][-1].content
    except Exception as e:
        return f"An error occurred in the reasoning loop: {str(e)}"
