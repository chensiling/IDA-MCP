"""Executable entry point for the standalone IDA-MCP server."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importing server loads ida_mcp.tools and performs the registration check.
from ida_mcp import server as _server  # noqa: E402, F401
from ida_mcp.standalone import main  # noqa: E402


if __name__ == '__main__':
    main()
