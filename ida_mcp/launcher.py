"""Helpers for launching the standalone server from embedded Python."""

import os
import sys


def _is_python_executable(path):
    if not path:
        return False
    name = os.path.basename(path).lower()
    return name.startswith("python") and os.path.isfile(path)


def find_python_executable():
    """Find the Python installation backing the embedded IDAPython runtime.

    In embedded IDAPython, ``sys.executable`` can be ``ida.exe``. Launching that
    with a .py argument makes IDA treat the script as an input binary. Only an
    explicit override or executables belonging to the embedded runtime's Python
    prefixes are considered; an unrelated Python from PATH could have different
    packages or an incompatible version.
    """
    override = os.environ.get("IDA_MCP_PYTHON")
    if override:
        override = os.path.abspath(
            os.path.expandvars(os.path.expanduser(override)))
        if _is_python_executable(override):
            return override
        raise RuntimeError(
            "IDA_MCP_PYTHON does not point to a valid Python executable: "
            f"{override}")

    candidates = [
        sys.executable,
        getattr(sys, "_base_executable", None),
    ]

    suffix = ".exe" if os.name == "nt" else ""
    versioned = f"python{sys.version_info.major}.{sys.version_info.minor}{suffix}"
    for prefix in dict.fromkeys((sys.prefix, sys.base_prefix)):
        if not prefix:
            continue
        if os.name == "nt":
            candidates.extend((
                os.path.join(prefix, "python.exe"),
                os.path.join(prefix, "pythonw.exe"),
                os.path.join(prefix, "Scripts", "python.exe"),
                os.path.join(prefix, "Scripts", "pythonw.exe"),
            ))
        else:
            candidates.extend((
                os.path.join(prefix, "bin", versioned),
                os.path.join(prefix, "bin", "python3"),
                os.path.join(prefix, "bin", "python"),
            ))

    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        candidate = os.path.abspath(os.path.expandvars(os.path.expanduser(candidate)))
        key = os.path.normcase(candidate)
        if key in seen:
            continue
        seen.add(key)
        if _is_python_executable(candidate):
            return candidate

    raise RuntimeError(
        "Could not locate the Python executable used by IDAPython. Set "
        "IDA_MCP_PYTHON to that interpreter and ensure the 'mcp' package is "
        "installed in the same environment.")
