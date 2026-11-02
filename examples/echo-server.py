#!/usr/bin/env python3
"""Tiny MCP-ish stdio server for trying mcp-jail. Not a real MCP implementation."""
import json, sys
TOOLS = [
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    {"name": "delete_file", "description": "Delete a file", "inputSchema": {"type": "object"}},
    {"name": "probe", "description": "Report what the server can see (home dir, network)", "inputSchema": {"type": "object"}},
]

def probe(args):
    import os, socket
    home = os.path.expanduser("~")
    try:
        socket.create_connection((args.get("host", "1.1.1.1"), int(args.get("port", 53))), timeout=2).close()
        net = "reachable"
    except OSError as e:
        net = "blocked:" + type(e).__name__
    sentinel = args.get("sentinel")
    out = {
        "home": home,
        "home_visible": os.path.isdir(home),
        "sentinel_visible": bool(sentinel) and os.path.exists(sentinel),
        "cwd": os.getcwd(),
        "net": net,
    }
    if args.get("dns"):  # name resolution as the server sees it
        try:
            out["dns"] = socket.gethostbyname(args["dns"])
        except OSError as e:
            out["dns"] = "error:" + type(e).__name__
    if args.get("url"):  # HTTP as the server sees it; proxy=false ignores HTTP_PROXY
        import urllib.request, urllib.error
        handlers = [] if args.get("proxy", True) else [urllib.request.ProxyHandler({})]
        try:
            with urllib.request.build_opener(*handlers).open(args["url"], timeout=5) as r:
                out["http"] = "status:%d" % r.status
        except urllib.error.HTTPError as e:
            out["http"] = "status:%d" % e.code
        except Exception as e:
            out["http"] = "error:" + type(e).__name__
    return out
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
        name = m["params"]["name"]
        text = json.dumps(probe(m["params"].get("arguments") or {})) if name == "probe" else "called " + name
        r = {"content": [{"type": "text", "text": text}]}
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n")
    sys.stdout.flush()
