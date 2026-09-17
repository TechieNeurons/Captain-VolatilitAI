import os
import sys
import json
import urllib.request
import concurrent.futures

import volatility3.plugins
from volatility3 import framework
from volatility3.framework import contexts, automagic, exceptions
from volatility3.framework import plugins as framework_plugins
from volatility3.framework import import_files

from volatility3.plugins.windows import info as win_info

def build_windows_plugin_catalog():
    """
    Introspects Volatility 3 directly and builds a ground-truth mapping
    of plugin names to their official documentation.
    """
    try:
        import_files(volatility3.plugins, True)
        all_plugins = framework.list_plugins()
        catalog = {}
        for name, cls in all_plugins.items():
            if name.startswith("windows."):
                doc = (cls.__doc__ or "No description available.").strip().split("\n")[0]
                catalog[name] = doc
        return catalog
    except Exception as e:
        print(f"[-] Failed to build plugin catalog: {e}")
        return {}

def run_single_plugin(args):
    image_path, project_dir, plugin_name = args

    from volatility3.plugins.windows import pslist, psscan, cmdline, cmdscan, netscan, modules, modscan, unloadedmodules, callbacks
    from volatility3.plugins.windows.malware import psxview, malfind, ldrmodules, hollowprocesses, pebmasquerade

    plugin_map = {
        "pslist": pslist.PsList, "psscan": psscan.PsScan, "psxview": psxview.PsXView,
        "cmdline": cmdline.CmdLine, "cmdscan": cmdscan.CmdScan, "netscan": netscan.NetScan,
        "modules": modules.Modules, "modscan": modscan.ModScan, "unloadedmodules": unloadedmodules.UnloadedModules,
        "callbacks": callbacks.Callbacks, "malfind": malfind.Malfind, "ldrmodules": ldrmodules.LdrModules,
        "hollowprocesses": hollowprocesses.HollowProcesses, "pebmasquerade": pebmasquerade.PebMasquerade
    }

    plugin_cls = plugin_map[plugin_name]

    try:
        ctx = contexts.Context()
        abs_path = os.path.abspath(image_path)
        ctx.config['automagic.LayerStacker.single_location'] = "file:" + urllib.request.pathname2url(abs_path)

        available_automagics = automagic.available(ctx)
        plugin_automagics = automagic.choose_automagic(available_automagics, plugin_cls)

        plugin = framework_plugins.construct_plugin(
            context=ctx, automagics=plugin_automagics, plugin=plugin_cls,
            base_config_path=f"plugins.{plugin_name}", progress_callback=None, open_method=None
        )

        treegrid = plugin.run()
        treegrid.populate()

        flat_nodes = treegrid.visit(None, collect_nodes, [])
        columns = [col.name for col in treegrid.columns]

        results = []
        for node in flat_nodes:
            row_dict = {}
            for i, col_name in enumerate(columns):
                row_dict[col_name] = str(node.values[i])
            results.append(row_dict)

        output_filename = os.path.join(project_dir, f"{plugin_name}.json")
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)

        return True, plugin_name
    except Exception as e:
        return False, f"{plugin_name} error: {str(e)}"

def run_dynamic_plugin(image_path, project_dir, plugin_req, kwargs_dict):
    """Executes a verified Volatility 3 plugin dynamically."""
    import_files(volatility3.plugins, True)
    plugins_dict = framework.list_plugins()

    target_class = plugins_dict.get(plugin_req)
    if not target_class:
        for name, cls in plugins_dict.items():
            if plugin_req.lower() == name.lower() or plugin_req.lower() in name.lower():
                target_class = cls
                plugin_req = name
                break

    if not target_class:
        return f"Error: Plugin '{plugin_req}' does not exist in Volatility 3.", []

    ctx = contexts.Context()
    ctx.config['automagic.LayerStacker.single_location'] = "file:" + urllib.request.pathname2url(os.path.abspath(image_path))

    base_config_path = "plugins.dynamic"
    for k, v in kwargs_dict.items():
        clean_v = str(v).strip().strip("\"'")
        if k.lower() == "pid":
            ctx.config[f"{base_config_path}.pid"] = [int(p.strip()) for p in clean_v.split(',')]
        elif k.lower() == "offset":
            ctx.config[f"{base_config_path}.offset"] = int(clean_v, 16) if clean_v.lower().startswith("0x") else int(clean_v)
        else:
            ctx.config[f"{base_config_path}.{k}"] = clean_v

    plugin_automagics = automagic.choose_automagic(automagic.available(ctx), target_class)

    try:
        plugin = framework_plugins.construct_plugin(ctx, plugin_automagics, target_class, base_config_path, None, None)
        treegrid = plugin.run()
        treegrid.populate()

        flat_nodes = treegrid.visit(None, collect_nodes, [])
        columns = [col.name for col in treegrid.columns]

        results = []
        for node in flat_nodes:
            row_dict = {}
            for i, col_name in enumerate(columns):
                row_dict[col_name] = str(node.values[i])
            results.append(row_dict)

        clean_name = plugin_req.split('.')[-1].lower()
        output_filename = os.path.join(project_dir, f"dynamic_{clean_name}.json")
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)

        return f"Success: {plugin_req} returned {len(results)} records. Saved to dynamic_{clean_name}.json", results
    except Exception as e:
        return f"Execution failed for {plugin_req}: {str(e)}", []

def clean_and_correlate_artifacts(project_dir):
    pslist_path = os.path.join(project_dir, "pslist.json")
    psscan_path = os.path.join(project_dir, "psscan.json")
    cmdline_path = os.path.join(project_dir, "cmdline.json")
    modules_path = os.path.join(project_dir, "modules.json")
    modscan_path = os.path.join(project_dir, "modscan.json")

    pslist_data = json.load(open(pslist_path, 'r', encoding='utf-8')) if os.path.exists(pslist_path) else []
    psscan_data = json.load(open(psscan_path, 'r', encoding='utf-8')) if os.path.exists(psscan_path) else []

    cmdline_map = {}
    if os.path.exists(cmdline_path):
        with open(cmdline_path, 'r', encoding='utf-8') as f:
            for item in json.load(f):
                cmdline_map[str(item.get("PID"))] = item.get("Args", "-")

    merged_processes = {}
    for proc in pslist_data:
        offset = proc.get("Offset(V)", proc.get("Offset", ""))
        pid = str(proc.get("PID", "-"))
        merged_processes[offset] = {
            "PID": pid, "PPID": str(proc.get("PPID", "-")),
            "ImageFileName": proc.get("ImageFileName", ""), "Offset(V)": offset,
            "Threads": proc.get("Threads", "0"), "CreateTime": proc.get("CreateTime", ""),
            "ExitTime": proc.get("ExitTime", "N/A"), "in_pslist": True, "in_psscan": False,
            "Args": cmdline_map.get(pid, "-")
        }

    for proc in psscan_data:
        offset = proc.get("Offset(V)", proc.get("Offset", ""))
        pid = str(proc.get("PID", "-"))
        if offset in merged_processes:
            merged_processes[offset]["in_psscan"] = True
        else:
            merged_processes[offset] = {
                "PID": pid, "PPID": str(proc.get("PPID", "-")),
                "ImageFileName": proc.get("ImageFileName", ""), "Offset(V)": offset,
                "Threads": proc.get("Threads", "0"), "CreateTime": proc.get("CreateTime", ""),
                "ExitTime": proc.get("ExitTime", "N/A"), "in_pslist": False, "in_psscan": True,
                "Args": cmdline_map.get(pid, "-")
            }

    for proc in merged_processes.values():
        proc["unlinked_dkom"] = (proc["in_psscan"] and not proc["in_pslist"])

    wininit_pid = next((p["PID"] for p in merged_processes.values() if p["ImageFileName"].lower() == "wininit.exe"), None)
    services_pid = next((p["PID"] for p in merged_processes.values() if p["ImageFileName"].lower() == "services.exe"), None)

    def is_legitimate_process(proc):
        if proc["unlinked_dkom"]: return False
        name, pid, ppid, args = proc["ImageFileName"].lower(), proc["PID"], proc["PPID"], proc["Args"].lower()

        if name == "system": return pid == "4" and ppid == "0"
        if name == "registry": return ppid == "4"
        if name == "smss.exe": return ppid == "4" and ("system32" in args or args == "-")
        if name == "csrss.exe": return "system32\\csrss.exe" in args
        if name == "wininit.exe": return "system32" in args or args == "-"
        if name == "services.exe": return (wininit_pid is None or ppid == wininit_pid) and ("system32\\services.exe" in args or args == "-")
        if name == "lsass.exe": return (wininit_pid is None or ppid == wininit_pid) and ("system32\\lsass.exe" in args or args == "-")
        if name == "winlogon.exe": return "winlogon.exe" in args
        if name == "svchost.exe":
            if any(bad in args for bad in ["downloads", "appdata", "temp", "users"]) or "-k" not in args: return False
            return services_pid is None or ppid == services_pid
        if name == "dwm.exe": return "dwm.exe" in args
        if name.startswith("fontdrvhost"): return args == "-" or "fontdrvhost" in args
        if name == "memcompression": return ppid == "4"
        if name in ["logonui.exe", "userinit.exe"] and proc["ExitTime"] != "N/A": return True
        return False

    with open(os.path.join(project_dir, "filtered_processes.json"), "w", encoding="utf-8") as f:
        json.dump([p for p in merged_processes.values() if not is_legitimate_process(p)], f, indent=4)

    modules_data = json.load(open(modules_path, 'r', encoding='utf-8')) if os.path.exists(modules_path) else []
    modscan_data = json.load(open(modscan_path, 'r', encoding='utf-8')) if os.path.exists(modscan_path) else []

    merged_modules = {}
    for mod in modules_data:
        base = mod.get("Base", "")
        merged_modules[base] = {
            "Name": mod.get("Name", ""), "Base": base, "Size": mod.get("Size", ""),
            "Path": mod.get("Path", "-"), "in_modules": True, "in_modscan": False
        }

    for mod in modscan_data:
        base = mod.get("Base", "")
        if base in merged_modules: merged_modules[base]["in_modscan"] = True
        else:
            merged_modules[base] = {
                "Name": mod.get("Name", ""), "Base": base, "Size": mod.get("Size", ""),
                "Path": mod.get("Path", "-"), "in_modules": False, "in_modscan": True
            }

    for mod in merged_modules.values():
        mod["unlinked_rootkit"] = (mod["in_modscan"] and not mod["in_modules"])

    def is_legitimate_module(mod):
        if mod["unlinked_rootkit"]: return False
        name, path = mod["Name"].lower(), mod["Path"].lower()
        if name in ["", "-", "none"] or path in ["", "-", "none"]: return False
        return any(path.startswith(vp) for vp in ["\\systemroot\\system32\\drivers\\", "\\systemroot\\system32\\driverstore\\", "\\systemroot\\system32\\"])

    with open(os.path.join(project_dir, "filtered_modules.json"), "w", encoding="utf-8") as f:
        json.dump([m for m in merged_modules.values() if not is_legitimate_module(m)], f, indent=4)

def analyze_windows_dump(image_path, project_dir, progress_cb=None):
    triage_list = [
        "pslist", "psscan", "psxview", "cmdline", "cmdscan", "netscan",
        "modules", "modscan", "unloadedmodules", "callbacks",
        "malfind", "ldrmodules", "hollowprocesses", "pebmasquerade"
    ]
    total_steps = len(triage_list) + 2
    current_step = 0

    if progress_cb: progress_cb(0.05, "Identifying OS and loading ISF (windows.info)...")

    ctx = contexts.Context()
    ctx.config['automagic.LayerStacker.single_location'] = "file:" + urllib.request.pathname2url(os.path.abspath(image_path))

    plugin = framework_plugins.construct_plugin(
        context=ctx, automagics=automagic.choose_automagic(automagic.available(ctx), win_info.Info), plugin=win_info.Info,
        base_config_path="plugins.info", progress_callback=None, open_method=None
    )

    treegrid = plugin.run()
    treegrid.populate()
    flat_nodes = treegrid.visit(None, collect_nodes, [])

    info_data = [{"Property": str(n.values[0]), "Value": str(n.values[1])} for n in flat_nodes]
    with open(os.path.join(project_dir, "image_info.json"), "w", encoding="utf-8") as f:
        json.dump(info_data, f, indent=4)

    current_step += 1

    tasks = [(image_path, project_dir, p) for p in triage_list]
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_single_plugin, arg): arg for arg in tasks}
        for future in concurrent.futures.as_completed(futures):
            success, msg = future.result()
            current_step += 1
            if progress_cb: progress_cb(current_step / total_steps, f"Finished {msg}")

    if progress_cb: progress_cb(0.95, "Running heuristic correlation engine...")
    clean_and_correlate_artifacts(project_dir)

    if progress_cb: progress_cb(1.0, "Triage complete!")

def collect_nodes(node, accumulator):
    accumulator.append(node)
    return accumulator
