import os
import sys
import json
import urllib.request
import concurrent.futures

import volatility3
from volatility3.framework import contexts, automagic, exceptions
from volatility3.framework import plugins as framework_plugins

# Windows info plugin
from volatility3.plugins.windows import info as win_info

def run_single_plugin(args):
    image_path, plugin_name = args

    from volatility3.plugins.windows import pslist, psscan, cmdline, cmdscan, netscan, modules, modscan, unloadedmodules, callbacks
    from volatility3.plugins.windows.malware import psxview, malfind, ldrmodules, hollowprocesses, pebmasquerade

    plugin_map = {
        "pslist": pslist.PsList,
        "psscan": psscan.PsScan,
        "psxview": psxview.PsXView,
        "cmdline": cmdline.CmdLine,
        "cmdscan": cmdscan.CmdScan,
        "netscan": netscan.NetScan,
        "modules": modules.Modules,
        "modscan": modscan.ModScan,
        "unloadedmodules": unloadedmodules.UnloadedModules,
        "callbacks": callbacks.Callbacks,
        "malfind": malfind.Malfind,
        "ldrmodules": ldrmodules.LdrModules,
        "hollowprocesses": hollowprocesses.HollowProcesses,
        "pebmasquerade": pebmasquerade.PebMasquerade
    }

    plugin_cls = plugin_map[plugin_name]
    print(f"[*] [Worker] Started scanning: {plugin_name}")

    try:
        # 1. Initialize a fresh context for this specific CPU process
        ctx = contexts.Context()
        abs_path = os.path.abspath(image_path)
        single_location = "file:" + urllib.request.pathname2url(abs_path)
        ctx.config['automagic.LayerStacker.single_location'] = single_location

        # 2. Automagic setup (Super fast now since the main thread already cached the ISF)
        available_automagics = automagic.available(ctx)
        plugin_automagics = automagic.choose_automagic(available_automagics, plugin_cls)

        plugin = framework_plugins.construct_plugin(
            context=ctx,
            automagics=plugin_automagics,
            plugin=plugin_cls,
            base_config_path=f"plugins.{plugin_name}",
            progress_callback=None,
            open_method=None
        )

        # 3. Execute plugin
        treegrid = plugin.run()
        treegrid.populate()

        # 4. Extract data
        flat_nodes = treegrid.visit(None, collect_nodes, [])
        columns = [col.name for col in treegrid.columns]

        results = []
        for node in flat_nodes:
            row_dict = {}
            for i, col_name in enumerate(columns):
                row_dict[col_name] = str(node.values[i])
            results.append(row_dict)

        # 5. Write to disk
        output_filename = f"{plugin_name}.json"
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)

        return f"[+] [Worker] Successfully finished {plugin_name} -> {output_filename}"

    except Exception as e:
        return f"[-] [Worker] ERROR in {plugin_name}: {e}"

def clean_and_correlate_artifacts():
    print("\n" + "=" * 60)
    print("[*] STARTING CORRELATION & HEURISTIC CLEANING PIPELINE")
    print("=" * 60)

    # =========================================================================
    # 1. PROCESS CORRELATION: Merge pslist, psscan, and cmdline
    # =========================================================================
    print("[*] Merging pslist, psscan, and cmdline...")

    with open("pslist.json", "r", encoding="utf-8") as f:
        pslist_data = json.load(f)

    with open("psscan.json", "r", encoding="utf-8") as f:
        psscan_data = json.load(f)

    cmdline_map = {}
    if os.path.exists("cmdline.json"):
        with open("cmdline.json", "r", encoding="utf-8") as f:
            for item in json.load(f):
                cmdline_map[str(item.get("PID"))] = item.get("Args", "-")

    # Index processes by Offset(V) to capture unallocated/carved EPROCESS blocks
    merged_processes = {}

    for proc in pslist_data:
        offset = proc["Offset(V)"]
        pid = str(proc["PID"])
        merged_processes[offset] = {
            "PID": pid,
            "PPID": str(proc.get("PPID", "-")),
            "ImageFileName": proc.get("ImageFileName", ""),
            "Offset(V)": offset,
            "Threads": proc.get("Threads", "0"),
            "CreateTime": proc.get("CreateTime", ""),
            "ExitTime": proc.get("ExitTime", "N/A"),
            "in_pslist": True,
            "in_psscan": False,
            "Args": cmdline_map.get(pid, "-")
        }

    for proc in psscan_data:
        offset = proc["Offset(V)"]
        pid = str(proc["PID"])
        if offset in merged_processes:
            merged_processes[offset]["in_psscan"] = True
        else:
            # Process was unlinked or carved (DKOM hidden or terminated!)
            merged_processes[offset] = {
                "PID": pid,
                "PPID": str(proc.get("PPID", "-")),
                "ImageFileName": proc.get("ImageFileName", ""),
                "Offset(V)": offset,
                "Threads": proc.get("Threads", "0"),
                "CreateTime": proc.get("CreateTime", ""),
                "ExitTime": proc.get("ExitTime", "N/A"),
                "in_pslist": False,
                "in_psscan": True,
                "Args": cmdline_map.get(pid, "-")
            }

    # Tag unlinked processes (Present in psscan but missing from active pslist)
    for proc in merged_processes.values():
        proc["unlinked_dkom"] = (proc["in_psscan"] and not proc["in_pslist"])

    # Locate wininit.exe PID dynamically to validate services.exe & lsass.exe parentage
    wininit_pid = None
    for proc in merged_processes.values():
        if proc["ImageFileName"].lower() == "wininit.exe":
            wininit_pid = proc["PID"]
            break

    # Locate services.exe PID dynamically to validate svchost.exe parentage
    services_pid = None
    for proc in merged_processes.values():
        if proc["ImageFileName"].lower() == "services.exe":
            services_pid = proc["PID"]
            break

    # =========================================================================
    # 2. HEURISTIC PROCESS FILTERING (Based on 0xcybery Core Processes)
    # =========================================================================
    print("[*] Filtering out legitimate Windows processes...")

    def is_legitimate_process(proc):
        # RULE 0: Never filter out DKOM unlinked processes!
        if proc["unlinked_dkom"]:
            return False

        name = proc["ImageFileName"].lower()
        pid = proc["PID"]
        ppid = proc["PPID"]
        args = proc["Args"].lower()

        # System: PID 4, PPID 0
        if name == "system":
            return pid == "4" and ppid == "0"

        # Registry: PPID 4
        if name == "registry":
            return ppid == "4"

        # smss.exe: PPID 4, runs from System32
        if name == "smss.exe":
            return ppid == "4" and ("system32" in args or args == "-")

        # csrss.exe: Runs from System32 with basesrv/winsrv parameters
        if name == "csrss.exe":
            return "system32\\csrss.exe" in args

        # wininit.exe: Spawns services and lsass, runs from System32
        if name == "wininit.exe":
            return "system32" in args or args == "-"

        # services.exe: Parent must be wininit.exe
        if name == "services.exe":
            return (wininit_pid is not None and ppid == wininit_pid) and ("system32\\services.exe" in args or args == "-")

        # lsass.exe: Parent must be wininit.exe, runs from System32
        if name == "lsass.exe":
            return (wininit_pid is not None and ppid == wininit_pid) and ("system32\\lsass.exe" in args or args == "-")

        # winlogon.exe: Runs from System32
        if name == "winlogon.exe":
            return "winlogon.exe" in args

        # svchost.exe: Parent MUST be services.exe, MUST have -k flag, CANNOT be in Downloads/Temp
        if name == "svchost.exe":
            has_k = "-k" in args
            is_child_of_services = (services_pid is not None and ppid == services_pid)
            in_bad_path = any(bad in args for bad in ["downloads", "appdata", "temp", "users"])
            
            # If it's running from a user directory or missing -k, it is MALWARE! Keep it!
            if in_bad_path or not has_k:
                return False
            return is_child_of_services

        # dwm.exe: Desktop Window Manager
        if name == "dwm.exe":
            return "dwm.exe" in args

        # fontdrvhost.exe: Font Driver Host
        if name.startswith("fontdrvhost"):
            return args == "-" or "fontdrvhost" in args

        # MemCompression: Parent is System (PID 4)
        if name == "memcompression":
            return ppid == "4"

        # Normal cleanly terminated session handlers
        if name in ["logonui.exe", "userinit.exe"] and proc["ExitTime"] != "N/A":
            return True

        return False

    suspicious_processes = [
        p for p in merged_processes.values() if not is_legitimate_process(p)
    ]

    with open("filtered_processes.json", "w", encoding="utf-8") as f:
        json.dump(suspicious_processes, f, indent=4)

    print(f"[+] Process analysis complete:")
    print(f"    - Total Merged: {len(merged_processes)}")
    print(f"    - Legitimate Filtered: {len(merged_processes) - len(suspicious_processes)}")
    print(f"    - Suspicious / Anomalies Retained: {len(suspicious_processes)} -> saved to filtered_processes.json")

    # =========================================================================
    # 3. MODULE CORRELATION & CLEANING: Merge modules and modscan
    # =========================================================================
    print("\n[*] Merging and filtering kernel modules (modules + modscan)...")

    with open("modules.json", "r", encoding="utf-8") as f:
        modules_data = json.load(f)

    with open("modscan.json", "r", encoding="utf-8") as f:
        modscan_data = json.load(f)

    merged_modules = {}

    for mod in modules_data:
        base = mod["Base"]
        merged_modules[base] = {
            "Name": mod.get("Name", ""),
            "Base": base,
            "Size": mod.get("Size", ""),
            "Path": mod.get("Path", "-"),
            "in_modules": True,
            "in_modscan": False
        }

    for mod in modscan_data:
        base = mod["Base"]
        if base in merged_modules:
            merged_modules[base]["in_modscan"] = True
        else:
            # Unlinked kernel driver or carved artifact!
            merged_modules[base] = {
                "Name": mod.get("Name", ""),
                "Base": base,
                "Size": mod.get("Size", ""),
                "Path": mod.get("Path", "-"),
                "in_modules": False,
                "in_modscan": True
            }

    for mod in merged_modules.values():
        mod["unlinked_rootkit"] = (mod["in_modscan"] and not mod["in_modules"])

    def is_legitimate_module(mod):
        # 1. Never filter unlinked modules (Potential DKOM Rootkits)
        if mod["unlinked_rootkit"]:
            return False

        name = mod["Name"].lower()
        path = mod["Path"].lower()

        # 2. Don't filter corrupt or empty driver structures carved by modscan
        if name in ["", "-", "none"] or path in ["", "-", "none"]:
            return False

        # 3. Standard Windows system driver paths
        valid_paths = [
            "\\systemroot\\system32\\drivers\\",
            "\\systemroot\\system32\\driverstore\\",
            "\\systemroot\\system32\\"
        ]
        
        # Must be in legitimate path AND loaded in active list
        if any(path.startswith(vp) for vp in valid_paths):
            return True

        return False

    suspicious_modules = [
        m for m in merged_modules.values() if not is_legitimate_module(m)
    ]

    with open("filtered_modules.json", "w", encoding="utf-8") as f:
        json.dump(suspicious_modules, f, indent=4)

    print(f"[+] Kernel Module analysis complete:")
    print(f"    - Total Merged: {len(merged_modules)}")
    print(f"    - Legitimate Filtered: {len(merged_modules) - len(suspicious_modules)}")
    print(f"    - Suspicious / Unlinked Modules Retained: {len(suspicious_modules)} -> saved to filtered_modules.json")
    print("=" * 60 + "\n")

def analyze_windows_dump(image_path):
    # 1. Initialize the Context
    ctx = contexts.Context()

    # 2. Format the file path for Volatility 3
    abs_path = os.path.abspath(image_path)
    single_location = "file:" + urllib.request.pathname2url(abs_path)
    ctx.config['automagic.LayerStacker.single_location'] = single_location

    # Gather available automagics
    available_automagics = automagic.available(ctx)

    # Choose the automagics required specifically for the windows.info plugin
    plugin_automagics = automagic.choose_automagic(available_automagics, win_info.Info)

    # 3. Construct the plugin
    # This is the magic step. Volatility will find the KDBG/PEB structures,
    # determine the exact Windows version, and download/load the correct ISF.
    plugin = framework_plugins.construct_plugin(
        context=ctx,
        automagics=plugin_automagics,
        plugin=win_info.Info,
        base_config_path="plugins",
        progress_callback=None,
        open_method=None
    )

    # 4. Run the plugin
    # This executes the plugin and returns a TreeGrid object containing the data
    treegrid = plugin.run()

    print("\n[+] Windows Memory Dump Successfully Identified and ISF Loaded!")
    print("-" * 60)

    treegrid.populate()
    flat_nodes = treegrid.visit(None, collect_nodes, [])

    for node in flat_nodes:
        # level = node.path_depth
        row_data = node.values

        print(f"{row_data[0]} = {row_data[1]}")

    print("-" * 60)

    # --- PHASE 2: Multiprocessing Triage Execution ---
    print("\n[*] Starting Multiprocessing Triage Plugins...")
    triage_list = [
        "pslist", "psscan", "psxview",
        "cmdline", "cmdscan", "netscan",
        "modules", "modscan", "malfind"
    ]

    # Package our arguments as tuples for the executor
    tasks = [(image_path, plugin) for plugin in triage_list]

    # Spawn 4 background worker processes
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
        for result_message in executor.map(run_single_plugin, tasks):
            print(result_message)

    print("\n[+] Triage completed. Check the local directory for JSON files.")

    # Calling the cleaning function
    print("\n[+] Cleaning before ingesting.")
    clean_and_correlate_artifacts()

def collect_nodes(node, accumulator):
    accumulator.append(node)
    return accumulator

if __name__ == "__main__":
    # Ensure the user provided exactly one argument (the memory dump path)
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path_to_memory_dump>")
        sys.exit(1)

    # Check if the file actually exists before running
    if not os.path.exists(sys.argv[1]):
        print(f"[-] Error: File '{sys.argv[1]}' does not exist.")
        sys.exit(1)

    analyze_windows_dump(sys.argv[1])
