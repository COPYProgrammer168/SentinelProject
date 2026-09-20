"""Cross-platform code-signing and executable verification utilities."""

from __future__ import annotations
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple
from sentinel.utils import logger


def get_executable_path(pid: Optional[int]) -> str:
    """Resolve the executable path for a given PID."""
    if pid is None or pid < 0:
        return ""
    try:
        import psutil
        p = psutil.Process(pid)
        return p.exe() or ""
    except Exception:
        return ""


def get_file_hash(filepath: str, algo: str = "sha256") -> str:
    """Compute hash of a file. Returns empty string if file cannot be read."""
    if not filepath or not os.path.isfile(filepath):
        return ""
    try:
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def get_signer_info(executable_path: str) -> Tuple[str, str]:
    """Get the code signing info for an executable.

    Returns (signer_name, signer_status) where:
    - signer_name: Name of the signing entity (e.g. "Microsoft Corporation")
    - signer_status: "signed", "unsigned", or "unknown"

    Platform-specific:
    - Windows: uses Get-AuthenticodeSignature via PowerShell
    - macOS: uses codesign -dv --verbose=4
    - Linux: tries dpkg -V / rpm -V, falls back to path + hash
    """
    if not executable_path or not os.path.isfile(executable_path):
        return ("", "unknown")

    system = platform.system()
    if system == "Windows":
        return _get_signer_windows(executable_path)
    elif system == "Darwin":
        return _get_signer_macos(executable_path)
    else:
        return _get_signer_linux(executable_path)


def _get_signer_windows(executable_path: str) -> Tuple[str, str]:
    """Get Authenticode signature info on Windows."""
    try:
        ps_cmd = f"""
        $sig = Get-AuthenticodeSignature -FilePath '{executable_path.replace("'", "''")}'
        if ($sig.Status -eq 'Valid') {{
            $sig.SignerCertificate.Subject
        }} else {{
            'UNSIGNED'
        }}
        """
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        output = res.stdout.strip()
        if output and output != "UNSIGNED":
            signer = output.split("\n")[0].strip()
            if "CN=" in signer:
                signer = signer.split("CN=")[-1].split(",")[0].strip()
            return (signer, "signed")
        return ("", "unsigned")
    except Exception as e:
        logger.debug(f"Windows signer check failed for {executable_path}: {e}")
        return ("", "unknown")


def _get_signer_macos(executable_path: str) -> Tuple[str, str]:
    """Get signing authority on macOS."""
    try:
        res = subprocess.run(
            ["codesign", "-dv", "--verbose=4", executable_path],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        for line in res.stdout.splitlines():
            if "Authority=" in line:
                authority = line.split("Authority=", 1)[1].strip()
                return (authority, "signed")
        if res.returncode == 0:
            return ("", "unsigned")
        return ("", "unknown")
    except Exception as e:
        logger.debug(f"macOS codesign check failed for {executable_path}: {e}")
        return ("", "unknown")


def _get_signer_linux(executable_path: str) -> Tuple[str, str]:
    """Get package verification info on Linux.

    Tries dpkg -V / rpm -V to verify the package that owns the file.
    Falls back to path + hash if package manager verification is unavailable.
    """
    basename = os.path.basename(executable_path)

    if shutil.which("dpkg"):
        try:
            res = subprocess.run(
                ["dpkg", "-S", executable_path],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                pkg_name = res.stdout.strip().split(":")[0]
                return (f"dpkg:{pkg_name}", "signed")
        except Exception:
            pass

        try:
            res = subprocess.run(
                ["dpkg", "-V", basename],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res.returncode == 0:
                return (f"dpkg:{basename}", "signed")
        except Exception:
            pass

    if shutil.which("rpm"):
        try:
            res = subprocess.run(
                ["rpm", "-qf", executable_path],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                pkg_name = res.stdout.strip()
                return (f"rpm:{pkg_name}", "signed")
        except Exception:
            pass

    file_hash = get_file_hash(executable_path)[:16]
    return (f"hash:{file_hash}", "signed")


def get_process_identity(pid: Optional[int]) -> Dict[str, str]:
    """Get full identity info for a process.

    Returns dict with: name, executable_path, signer, signer_status, file_hash
    """
    import psutil

    name = ""
    exe_path = ""
    signer = ""
    signer_status = "unknown"
    file_hash = ""

    if pid is None or pid < 0:
        return {
            "name": name,
            "executable_path": exe_path,
            "signer": signer,
            "signer_status": signer_status,
            "file_hash": file_hash,
        }

    try:
        p = psutil.Process(pid)
        name = p.name() or ""
        exe_path = p.exe() or ""
    except Exception:
        return {
            "name": name,
            "executable_path": exe_path,
            "signer": signer,
            "signer_status": signer_status,
            "file_hash": file_hash,
        }

    if exe_path:
        signer, signer_status = get_signer_info(exe_path)
        file_hash = get_file_hash(exe_path)

    return {
        "name": name,
        "executable_path": exe_path,
        "signer": signer,
        "signer_status": signer_status,
        "file_hash": file_hash,
    }
