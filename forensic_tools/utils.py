"""
Shared utilities and constants for forensic tools
"""

import os
import sys
import time
import atexit
import signal
from typing import Optional, Dict
from pathlib import Path

# Constants
APP_TITLE = "USB Write Blocker + Imager"
APP_VERSION = "v2.2.0"
IS_WINDOWS = (os.name == "nt")

# Global registry state for cleanup
_global_write_block_state = {
    "enabled": False,
    "key_path": r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
}


# ---------------- Cleanup Handlers ----------------
def _cleanup_write_block():
    """Cleanup handler - clears all write protection registry keys on exit."""
    if not _global_write_block_state["enabled"]:
        return
    
    import winreg
    
    # Clear Method 1: StorageDevicePolicies
    try:
        key_path = _global_write_block_state["key_path"]
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "WriteProtect", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(k)
    except Exception:
        pass
    
    # Clear Method 2: Group Policy - Removable Storage
    try:
        guid_removable = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        key_path_gp = rf"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{guid_removable}"
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path_gp, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "Deny_Write", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(k)
    except Exception:
        pass
    
    _global_write_block_state["enabled"] = False


def _signal_handler(signum, frame):
    _cleanup_write_block()
    sys.exit(0)


# Register cleanup handlers
atexit.register(_cleanup_write_block)
if IS_WINDOWS:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    try:
        import win32api
        win32api.SetConsoleCtrlHandler(_signal_handler, True)
    except ImportError:
        pass


# ---------------- Tool Executables ----------------
def _get_all_search_paths() -> list:
    paths = []
    
    # HIGHEST PRIORITY: PyInstaller extraction directory (sys._MEIPASS)
    # This is where bundled files (from datas= in spec) are extracted
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        meipass = sys._MEIPASS
        paths.append(os.path.join(meipass, "tsk_bin"))
        paths.append(meipass)
    
    # Next: next to executable (for --onedir or external files)
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        paths.append(os.path.join(exe_dir, "tsk_bin"))
        paths.append(exe_dir)
    
    # Script mode: project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    paths.append(os.path.join(project_root, "tsk_bin"))
    paths.append(project_root)
    
    # Current working directory
    cwd = os.getcwd()
    paths.append(os.path.join(cwd, "tsk_bin"))
    paths.append(cwd)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    
    return unique_paths


def find_dd_executable() -> Optional[str]:
    search_paths = _get_all_search_paths()
    
    for search_dir in search_paths:
        dd_path = os.path.join(search_dir, "dd.exe")
        if os.path.isfile(dd_path):
            return dd_path
    
    return None


def find_ewfacquire_executable() -> Optional[str]:
    search_paths = _get_all_search_paths()
    
    for search_dir in search_paths:
        # Try ewfacquire first (preferred)
        ewf_path = os.path.join(search_dir, "ewfacquire.exe")
        if os.path.isfile(ewf_path):
            return ewf_path
        # Also try ewfacquirestream as fallback
        ewf_path = os.path.join(search_dir, "ewfacquirestream.exe")
        if os.path.isfile(ewf_path):
            return ewf_path
    
    return None


def get_tool_search_debug_info() -> str:
    lines = []
    lines.append(f"Frozen: {getattr(sys, 'frozen', False)}")
    if getattr(sys, 'frozen', False):
        lines.append(f"Executable: {sys.executable}")
        lines.append(f"Exe dir: {os.path.dirname(sys.executable)}")
        if hasattr(sys, '_MEIPASS'):
            lines.append(f"MEIPASS: {sys._MEIPASS}")
    lines.append(f"Script file: {os.path.abspath(__file__)}")
    lines.append(f"CWD: {os.getcwd()}")
    lines.append("Search paths:")
    for p in _get_all_search_paths():
        exists = os.path.isdir(p)
        lines.append(f"  {p} [{'EXISTS' if exists else 'NOT FOUND'}]")
    
    # Check for specific files
    lines.append("Tool status:")
    dd = find_dd_executable()
    ewf = find_ewfacquire_executable()
    lines.append(f"  dd.exe: {dd if dd else 'NOT FOUND'}")
    lines.append(f"  ewfacquire.exe: {ewf if ewf else 'NOT FOUND'}")
    
    return "\n".join(lines)


# ---------------- Report Writer ----------------
def write_report(
    output_file: Path,
    device_info: Dict,
    start_ts: float,
    end_ts: float,
    expected: int,
    copied: int,
    md5: str,
    sha1: str,
    status: str,
    method: str = "dd",
    sha256: str = ""
) -> str:
    report_path = output_file.with_suffix(".txt")
    
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"{APP_TITLE} {APP_VERSION} - Forensic Imaging Report\n")
            f.write("=" * 80 + "\n\n")

            f.write("OPERATION DETAILS\n" + "-" * 40 + "\n")
            f.write(f"Report Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
            try:
                f.write(f"Operator: {os.getlogin()}\n")
            except Exception:
                f.write("Operator: N/A\n")
            f.write(f"System: {os.environ.get('COMPUTERNAME', 'Unknown')}\n")
            f.write(f"Imaging Method: {method}\n")
            f.write(f"Status: {status}\n\n")

            f.write("DEVICE INFORMATION\n" + "-" * 40 + "\n")
            f.write(f"Drive Letter: {device_info.get('drive_letter', 'N/A')}\n")
            f.write(f"Physical Drive: {device_info.get('physical', 'N/A')}\n")
            f.write(f"Vendor: {device_info.get('vendor') or 'N/A'}\n")
            f.write(f"Product: {device_info.get('product') or 'N/A'}\n")
            f.write(f"Serial Number: {device_info.get('serial') or 'N/A'}\n")
            size_gb = expected/(1024**3) if expected > 0 else 0
            f.write(f"Device Size: {expected:,} bytes ({size_gb:.2f} GB)\n")
            f.write(f"Output File: {output_file}\n")
            if copied:
                out_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
                f.write(f"Output Size: {out_size:,} bytes ({out_size/(1024**3):.2f} GB)\n")
            f.write("\n")

            f.write("TIMING INFORMATION\n" + "-" * 40 + "\n")
            f.write(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_ts))}\n")
            f.write(f"End: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_ts))}\n")
            duration = max(0.01, end_ts - start_ts)
            f.write(f"Duration: {duration:.2f} seconds\n")
            if copied and duration > 0:
                mbps = (copied / 1048576.0) / max(duration, 0.01)
                f.write(f"Average Speed: {mbps:.2f} MB/s\n")
            f.write("\n")

            if md5 or sha1 or sha256:
                f.write("HASH VERIFICATION\n" + "-" * 40 + "\n")
                f.write(f"MD5:     {md5 if md5 else 'N/A'}\n")
                f.write(f"SHA-1:   {sha1 if sha1 else 'N/A'}\n")
                if sha256:
                    f.write(f"SHA-256: {sha256}\n")
                f.write("\n")

            f.write("CHAIN OF CUSTODY NOTES\n" + "-" * 40 + "\n")
            f.write("(Add your notes here)\n\n")

            f.write("=" * 80 + "\n")
            f.write("End of Report\n")
            f.write("=" * 80 + "\n")

        return str(report_path)
    except Exception as e:
        return f"Failed to write report: {e}"


# Export write block state for usb_blocker module
def get_write_block_state():
    return _global_write_block_state
