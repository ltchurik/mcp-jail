#!/usr/bin/env python3
"""Tiny MCP-ish Streamable HTTP server for trying mcp-jail with server.url.
Not a real MCP implementation. Listens on 127.0.0.1:<port> (0 = pick one,
printed on stdout) and serves /mcp: POST answers requests (tools/call on an
SSE stream, the rest as JSON), notifications get 202, GET sends one
notification and closes, DELETE ends the session."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    {"name": "delete_file", "description": "Delete a file", "inputSchema": {"type": "object"}},
]
PROMPTS = [{"name": "summarize", "description": "Summarize a document", "arguments": []}]
SESSION = "e2e-session"

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _json(self, status, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers: self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def _sse(self, events):
        body = "".join("data: %s\n\n" % json.dumps(e) for e in events).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        if self.path != "/mcp": self.send_response(404); self.end_headers(); return
        m = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if "id" not in m:
            self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers(); return
        meth = m.get("method")
        if meth != "initialize" and self.headers.get("Mcp-Session-Id") != SESSION:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        if meth == "initialize":
            r = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "echo-http", "version": "0"}}
            return self._json(200, {"jsonrpc": "2.0", "id": m["id"], "result": r}, [("Mcp-Session-Id", SESSION)])
        if meth == "tools/list": r = {"tools": TOOLS}
        elif meth == "prompts/list": r = {"prompts": PROMPTS}
        elif meth == "prompts/get": r = {"messages": []}
        elif meth == "tools/call":
            text = "called " + m["params"]["name"] + " with " + ", ".join(k + "=" + str(v) for k, v in sorted((k.lower(), v) for k, v in self.headers.items()) if k in ("authorization", "x-e2e"))
            return self._sse([{"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "working"}},
                              {"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": text}]}}])
        else: r = {}
        self._json(200, {"jsonrpc": "2.0", "id": m["id"], "result": r})

    def do_GET(self):
        if self.path != "/mcp" or self.headers.get("Mcp-Session-Id") != SESSION:
            self.send_response(405); self.send_header("Content-Length", "0"); self.end_headers(); return
        self._sse([{"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hello from GET"}}])

    def do_DELETE(self):
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
