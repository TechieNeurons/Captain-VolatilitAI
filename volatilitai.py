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

    from volatility3.plugins.windows import pslist, psscan, cmdline, cmdscan, netscan, modules, modscan
    from volatility3.plugins.windows.malware import psxview, malfind

    plugin_map = {
        "pslist": pslist.PsList,
        "psscan": psscan.PsScan,
        "psxview": psxview.PsXView,
        "cmdline": cmdline.CmdLine,
        "cmdscan": cmdscan.CmdScan,
        "netscan": netscan.NetScan,
        "modules": modules.Modules,
        "modscan": modscan.ModScan,
        "malfind": malfind.Malfind
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
