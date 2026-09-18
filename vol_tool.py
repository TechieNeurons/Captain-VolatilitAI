import subprocess
from database import SessionLocal, VolatilityCache

def run_volatility_plugin(project_id: int, dump_path: str, plugin: str, args: str = "") -> str:
    """
    Executes a Volatility 3 plugin. Caches the output to avoid re-running on the same memory dump.
    """
    db = SessionLocal()
    command_str = f"{plugin} {args}".strip()
    
    # 1. Check if we already ran this plugin for this project
    cached = db.query(VolatilityCache).filter_by(
        project_id=project_id, 
        plugin_command=command_str
    ).first()
    
    if cached:
        db.close()
        return f"[CACHED RESULT]\n{cached.output_json}"

    # 2. Build the Volatility 3 command (outputting to JSON)
    cmd = ["vol", "-f", dump_path, "-r", "json", plugin]
    if args:
        cmd.extend(args.split())
    
    try:
        # Run the command and capture output
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
        
        # 3. Cache the successful result
        new_cache = VolatilityCache(
            project_id=project_id, 
            plugin_command=command_str, 
            output_json=output
        )
        db.add(new_cache)
        db.commit()
        db.close()
        
        return f"[NEW RESULT]\n{output}"
        
    except subprocess.CalledProcessError as e:
        db.close()
        return f"[ERROR] Failed to run plugin. Stderr: {e.stderr}"
