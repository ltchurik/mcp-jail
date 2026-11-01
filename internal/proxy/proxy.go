// Package proxy brokers JSON-RPC between an MCP client (on our stdin/stdout)
// and the jailed MCP server (on its stdin/stdout), enforcing the policy.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

const maxLine = 64 << 20 // 64 MiB per JSON-RPC line

// Proxy holds the broker state.
type Proxy struct {
	Policy *policy.Policy
	Audit  *audit.Logger
	Logf   func(format string, args ...any) // stderr logger

	client io.Writer // to MCP client
	server io.Writer // to jailed server
	cmu    sync.Mutex
	smu    sync.Mutex

	pmu     sync.Mutex
	pending map[string]pendingReq

	tainted bool // rug-pull detected; all tool calls denied
	tty     *os.File
}

type pendingReq struct {
	method string
	tool   string
	start  time.Time
}

// Run brokers until either side closes. clientIn is our stdin, clientOut our
// stdout; serverIn/serverOut are the jailed server's stdin/stdout.
func (p *Proxy) Run(clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	p.client, p.server = clientOut, serverIn
	p.pending = map[string]pendingReq{}
	errc := make(chan error, 2)
	go func() { errc <- p.pump(clientIn, p.fromClient) }()
	go func() { errc <- p.pump(serverOut, p.fromServer) }()
	err := <-errc
	if p.tty != nil {
		p.tty.Close()
	}
	return err
}

func (p *Proxy) pump(r io.Reader, handle func([]byte)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), maxLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		handle(cp)
	}
	return sc.Err()
}

func (p *Proxy) toClient(b []byte) {
	p.cmu.Lock()
	defer p.cmu.Unlock()
	_, _ = p.client.Write(append(b, '\n'))
}

func (p *Proxy) toServer(b []byte) {
	p.smu.Lock()
	defer p.smu.Unlock()
	_, _ = p.server.Write(append(b, '\n'))
}

// fromClient handles one message coming from the MCP client.
func (p *Proxy) fromClient(line []byte) {
	m, err := jsonrpc.Parse(line)
	if err != nil {
		p.toServer(line) // not ours to judge
		return
	}
	if m.IsRequest() {
		pr := pendingReq{method: m.Method, start: time.Now()}
		if m.Method == "tools/call" {
			var tc jsonrpc.ToolCallParams
			_ = json.Unmarshal(m.Params, &tc)
			pr.tool = tc.Name
			if !p.allowCall(m, tc) {
				return
			}
		}
		p.pmu.Lock()
		p.pending[m.IDKey()] = pr
		p.pmu.Unlock()
	}
	p.toServer(line)
}

// allowCall applies tools policy. Returns false if the call was answered
// with an error and must not be forwarded.
func (p *Proxy) allowCall(m *jsonrpc.Message, tc jsonrpc.ToolCallParams) bool {
	var args json.RawMessage
	if p.Policy.Audit.Args {
		args = tc.Arguments
	}
	if p.tainted {
		p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "deny", Reason: "rug-pull pending approval", Args: args})
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: tool definitions changed; run `mcp-jail approve "+p.Policy.Name+"`"))
		return false
	}
	d := p.Policy.Decide(tc.Name)
	switch d {
	case policy.Allow:
		p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "allow", Args: args})
		return true
	case policy.Deny:
		p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "deny", Reason: "policy", Args: args})
		p.Logf("deny tools/call %s (policy)", tc.Name)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodePolicyDenied, "mcp-jail: tool "+tc.Name+" denied by policy"))
		return false
	default: // ask
		ok, how := p.ask(tc)
		if ok {
			p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "ask_allow", Reason: how, Args: args})
			return true
		}
		p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "ask_deny", Reason: how, Args: args})
		p.Logf("deny tools/call %s (%s)", tc.Name, how)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeAskRejected, "mcp-jail: tool "+tc.Name+" not approved ("+how+")"))
		return false
	}
}

// ask prompts on the controlling terminal. Without one, the answer is no.
func (p *Proxy) ask(tc jsonrpc.ToolCallParams) (bool, string) {
	if p.tty == nil {
		f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return false, "no tty"
		}
		p.tty = f
	}
	args := string(tc.Arguments)
	if len(args) > 400 {
		args = args[:400] + "…"
	}
	fmt.Fprintf(p.tty, "\n[mcp-jail] %s wants to call %s\n  args: %s\n  allow? [y/N] ", p.Policy.Name, tc.Name, args)
	rd := bufio.NewReader(p.tty)
	ans, err := rd.ReadString('\n')
	if err != nil {
		return false, "tty read error"
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans == "y" || ans == "yes" {
		return true, "tty"
	}
	return false, "user"
}

// fromServer handles one message coming from the jailed server.
func (p *Proxy) fromServer(line []byte) {
	m, err := jsonrpc.Parse(line)
	if err != nil {
		p.toClient(line)
		return
	}
	if m.IsResponse() {
		p.pmu.Lock()
		pr, ok := p.pending[m.IDKey()]
		delete(p.pending, m.IDKey())
		p.pmu.Unlock()
		if ok {
			switch pr.method {
			case "tools/list":
				if !p.checkLock(m) {
					return
				}
			case "tools/call":
				ev := audit.Event{Kind: "tool_result", Tool: pr.tool, Duration: time.Since(pr.start)}
				if m.Error != nil {
					ev.Error = m.Error.Message
				}
				p.Audit.Log(ev)
			}
		}
	}
	p.toClient(line)
}

// checkLock enforces rug-pull protection on a tools/list response. Returns
// false when the response was replaced with an error.
func (p *Proxy) checkLock(m *jsonrpc.Message) bool {
	if !p.Policy.Lock.Enabled || m.Error != nil {
		return true
	}
	var res jsonrpc.ToolsListResult
	if err := json.Unmarshal(m.Result, &res); err != nil {
		p.Logf("tools/list: cannot parse result: %v", err)
		return true
	}
	hash, per, err := lock.Compute(res.Tools)
	if err != nil {
		p.Logf("tools/list: cannot hash: %v", err)
		return true
	}
	cur, err := lock.Load(p.Policy.Name)
	if err != nil {
		p.Logf("lock: %v", err)
		return true
	}
	now := time.Now().UTC()
	if cur == nil {
		f := &lock.File{Name: p.Policy.Name, Hash: hash, Tools: per, CreatedAt: now, UpdatedAt: now}
		if err := lock.Save(f); err != nil {
			p.Logf("lock: save: %v", err)
		}
		p.Audit.Log(audit.Event{Kind: "lock", Decision: "created", Reason: hash[:12]})
		p.Logf("lock: recorded %d tools (%s)", len(per), hash[:12])
		return true
	}
	if cur.Hash == hash {
		p.tainted = false
		return true
	}
	d := lock.Compare(cur.Tools, per)
	_ = lock.SavePending(&lock.Pending{Name: p.Policy.Name, Hash: hash, Tools: per, SeenAt: now})
	p.tainted = true
	reason := fmt.Sprintf("added=%v removed=%v changed=%v", d.Added, d.Removed, d.Changed)
	p.Audit.Log(audit.Event{Kind: "lock", Decision: "blocked", Reason: reason})
	p.Logf("RUG-PULL: tool definitions changed: %s", reason)
	p.Logf("          inspect with `mcp-jail diff %s`, accept with `mcp-jail approve %s`", p.Policy.Name, p.Policy.Name)
	p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull,
		"mcp-jail: tool definitions changed since last approval ("+reason+"); run `mcp-jail approve "+p.Policy.Name+"`"))
	return false
}
