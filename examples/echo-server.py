#!/usr/bin/env python3
"""Tiny MCP-ish stdio server for trying mcp-jail. Not a real MCP implementation."""
import json, sys
TOOLS = [
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    {"name": "delete_file", "description": "Delete a file", "inputSchema": {"type": "object"}},
]
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if "id" not in m:
        continue
    if m.get("method") == "initialize":
        r = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "echo", "version": "0"}}
    elif m.get("method") == "tools/list":
        r = {"tools": TOOLS}
    elif m.get("method") == "tools/call":
        r = {"content": [{"type": "text", "text": "called " + m["params"]["name"]}]}
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n")
    sys.stdout.flush()
