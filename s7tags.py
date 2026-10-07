#!/usr/bin/env python3
"""Manage the s7comm-tags Wireshark plugin and its tag definitions.

    python s7tags.py install my_tags.csv     install the plugin, with a tag CSV
    python s7tags.py add more_tags.csv       add another tag CSV (same file name: replaces it)
    python s7tags.py replace new_tags.csv    remove the installed tag CSVs, use this one instead
    python s7tags.py remove old_tags.csv     remove one installed tag CSV
    python s7tags.py list                    show what is installed
    python s7tags.py uninstall               remove the plugin and all tag CSVs

Restart Wireshark after `install`. After changing tag CSVs only, Ctrl+R is enough.
"""
import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN = "s7comm_tags.lua"
DATA_DIR = "s7comm_tags_data"
REQUIRED_COLUMNS = ("tag name", "address", "data type")
TSHARK_CANDIDATES = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
)


def lua_plugins_dir():
    """Wireshark's personal Lua plugins folder, asked from tshark when possible."""
    tshark = shutil.which("tshark") or next((p for p in TSHARK_CANDIDATES if os.path.exists(p)), None)
    if tshark:
        try:
            out = subprocess.run([tshark, "-G", "folders"], capture_output=True, text=True,
                                 timeout=30).stdout
            for line in out.splitlines():
                name, sep, value = line.partition(":\t")
                if sep and name.strip() == "Personal Lua Plugins":
                    return Path(value.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Wireshark" / "plugins"
    return Path.home() / ".local" / "lib" / "wireshark" / "plugins"


def count_tags(csv_path):
    """Number of rows in a tag CSV; exits with a clear message if columns are missing."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        columns = {(c or "").strip().lower() for c in (reader.fieldnames or [])}
        missing = [c for c in REQUIRED_COLUMNS if c not in columns]
        if missing:
            sys.exit(f"Error: {csv_path} is missing the column(s): {', '.join(missing)}. "
                     "A tag CSV needs: Tag Name, Address, Data Type.")
        return sum(1 for _ in reader)


def copy_plugin(plugins, data):
    plugins.mkdir(parents=True, exist_ok=True)
    data.mkdir(exist_ok=True)
    shutil.copy(Path(__file__).with_name(PLUGIN), plugins / PLUGIN)


def check_csvs(paths):
    """Validate tag CSVs before anything is changed. Returns [(path, tag count)]."""
    for path in paths:
        if not Path(path).is_file():
            sys.exit(f"Error: file not found: {path}")
    return [(Path(p), count_tags(p)) for p in paths]


def copy_csvs(data, checked):
    for path, count in checked:
        shutil.copy(path, data / path.name)
        print(f"Added {count} tags from {path.name}")


def require_plugin(plugins):
    if not (plugins / PLUGIN).exists():
        sys.exit("Error: the plugin is not installed yet. Run:  python s7tags.py install <tags.csv>")


def cmd_install(args, plugins, data):
    checked = check_csvs(args.csv)
    copy_plugin(plugins, data)
    print(f"Installed the plugin: {plugins / PLUGIN}")
    copy_csvs(data, checked)
    if not any(data.glob("*.csv")):
        print("No tag CSV is installed yet, so nothing will be decoded. "
              "Add one with:  python s7tags.py add <tags.csv>")
    print("Restart Wireshark.")


def cmd_add(args, plugins, data):
    require_plugin(plugins)
    copy_csvs(data, check_csvs(args.csv))
    print("In Wireshark press Ctrl+R to reload the capture.")


def cmd_replace(args, plugins, data):
    require_plugin(plugins)
    checked = check_csvs(args.csv)
    for old in sorted(data.glob("*.csv")):
        old.unlink()
        print(f"Removed {old.name}")
    copy_csvs(data, checked)
    print("In Wireshark press Ctrl+R to reload the capture.")


def cmd_remove(args, plugins, data):
    targets = []
    for name in args.name:
        target = data / Path(name).name
        if target.suffix.lower() != ".csv":
            target = target.with_name(target.name + ".csv")
        if not target.is_file():
            sys.exit(f"Error: no installed tag CSV named {target.name}. See:  python s7tags.py list")
        targets.append(target)
    for target in targets:
        target.unlink()
        print(f"Removed {target.name}")
    print("In Wireshark press Ctrl+R to reload the capture.")


def cmd_list(args, plugins, data):
    installed = sorted(data.glob("*.csv")) if data.is_dir() else []
    print(f"Plugin: {plugins / PLUGIN} ({'installed' if (plugins / PLUGIN).exists() else 'NOT installed'})")
    for file in installed:
        print(f"  {file.name}: {count_tags(file)} tags")
    if not installed:
        command = "add" if (plugins / PLUGIN).exists() else "install"
        print(f"  No tag CSVs installed. Add one with:  python s7tags.py {command} <tags.csv>")


def cmd_uninstall(args, plugins, data):
    (plugins / PLUGIN).unlink(missing_ok=True)
    shutil.rmtree(data, ignore_errors=True)
    print("s7comm-tags was removed. Restart Wireshark to finish.")


def main():
    parser = argparse.ArgumentParser(prog="s7tags.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--plugins-dir", metavar="DIR",
                        help="Wireshark personal Lua plugins folder (found automatically by default)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    p = sub.add_parser("install", help="install or update the plugin, optionally with tag CSVs")
    p.add_argument("csv", nargs="*", help="tag CSV (columns: Tag Name, Address, Data Type)")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("add", help="add tag CSVs; a CSV with the same file name is replaced")
    p.add_argument("csv", nargs="+", help="tag CSV (columns: Tag Name, Address, Data Type)")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("replace", help="remove all installed tag CSVs and use the given ones instead")
    p.add_argument("csv", nargs="+", help="tag CSV (columns: Tag Name, Address, Data Type)")
    p.set_defaults(func=cmd_replace)

    p = sub.add_parser("remove", help="remove installed tag CSVs by file name")
    p.add_argument("name", nargs="+", help="file name as shown by `list`")
    p.set_defaults(func=cmd_remove)

    p = sub.add_parser("list", help="show the installed tag CSVs")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("uninstall", help="remove the plugin and all tag CSVs")
    p.set_defaults(func=cmd_uninstall)

    args = parser.parse_args()
    plugins = Path(args.plugins_dir) if args.plugins_dir else lua_plugins_dir()
    args.func(args, plugins, plugins / DATA_DIR)


if __name__ == "__main__":
    main()
