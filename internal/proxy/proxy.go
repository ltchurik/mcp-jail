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
	"sync/atomic"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/control"
	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

const maxLine = 64 << 20 // 64 MiB per JSON-RPC line

// Proxy holds the broker state.
type Proxy struct {
	// Policy is the policy the jail started with. Its tools and ask
	// sections can be replaced at runtime by Reload; everything else
	// (sandbox, network, lock, audit) is fixed for the life of the jail.
	Policy *policy.Policy
	Audit  *audit.Logger
	Logf   func(format string, args ...any) // stderr logger
	// TTYPath is the terminal used for `ask`; "" means /dev/tty. Tests point
	// it at a path that does not exist.
	TTYPath string
	// Asks, when set, lets an attached dashboard answer `ask` decisions that
	// have no terminal (see package control). nil: terminal or webhook only.
	Asks *control.Broker

	// live is the policy in force: Policy with the tools/ask sections of
	// the latest successful Reload. nil until the first Reload.
	live atomic.Pointer[policy.Policy]

	client io.Writer // to MCP client
	server io.Writer // to jailed server
	cmu    sync.Mutex
	smu    sync.Mutex

	pmu     sync.Mutex
	pending map[string]pendingReq

	// Lock state per list kind (tools, prompts, resources, templates).
	// Guarded by lmu; lcond wakes callers parked in waitVerified.
	lmu      sync.Mutex
	lcond    *sync.Cond
	sections map[lock.Kind]*lockState

	tty *os.File
}

// lockState tracks one locked list within a session. verified: this
// session's list matched the lock. inflight: list requests awaiting a
// response. tainted: a mismatch was seen.
type lockState struct {
	verified bool
	tainted  bool
	inflight int
	why      string // reason for the taint when it was not a hash mismatch
}

type pendingReq struct {
	method string
	tool   string
	start  time.Time
}

// gate maps a "use" method to the list it depends on and to the list method
// a client must have called first. resources/read is also refused while the
// resource templates are tainted (see waitVerified).
var gate = map[string]lock.Kind{
	"tools/call":     lock.Tools,
	"prompts/get":    lock.Prompts,
	"resources/read": lock.Resources,
}

func listMethod(k lock.Kind) string {
	for _, m := range []string{"tools/list", "prompts/list", "resources/list", "resources/templates/list"} {
		if lock.KindOf(m) == k {
			return m
		}
	}
	return string(k)
}

// Run brokers until either side closes. clientIn is our stdin, clientOut our
// stdout; serverIn/serverOut are the jailed server's stdin/stdout.
func (p *Proxy) Run(clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	p.client, p.server = clientOut, serverIn
	p.pending = map[string]pendingReq{}
	p.lcond = sync.NewCond(&p.lmu)
	p.sections = map[lock.Kind]*lockState{}
	for _, k := range lock.Kinds {
		p.sections[k] = &lockState{verified: !p.Policy.Lock.Enabled}
	}
	errc := make(chan error, 2)
	go func() { errc <- p.pump(clientIn, p.fromClient) }()
	go func() { errc <- p.pump(serverOut, p.fromServer) }()
	err := <-errc
	p.lmu.Lock()
	for _, st := range p.sections {
		st.tainted = true // release anyone parked in waitVerified with a deny
	}
	p.lcond.Broadcast()
	p.lmu.Unlock()
	if p.tty != nil {
		_ = p.tty.Close()
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

// fromClient handles one message coming from the MCP client. Only what
// the proxy could parse and judge is forwarded: a line that is not a single
// well-formed object (a batch, trailing data, a key that would read
// differently here and in the server) is answered with an error and
// dropped, and a notification that names a gated method is dropped, since
// a server may act on it and the proxy could not have checked it.
func (p *Proxy) fromClient(line []byte) {
	m, err := jsonrpc.Parse(line)
	if err != nil {
		p.Audit.Log(audit.Event{Kind: "protocol", Decision: "deny", Reason: "client: " + err.Error()})
		p.Logf("refused client message: %v", err)
		p.toClient(jsonrpc.NewErrorResponse(nil, jsonrpc.CodeInvalidRequest, "mcp-jail: "+err.Error()))
		return
	}
	if m.IsNotification() {
		if _, gated := gate[m.Method]; gated {
			p.Audit.Log(audit.Event{Kind: "protocol", Decision: "deny", Reason: "client: " + m.Method + " as a notification"})
			p.Logf("dropped %s notification: a gated method needs an id", m.Method)
			return
		}
	}
	if m.IsRequest() {
		pr := pendingReq{method: m.Method, start: time.Now()}
		if k := lock.KindOf(m.Method); k != "" {
			p.lmu.Lock()
			p.sections[k].inflight++
			p.lmu.Unlock()
		}
		switch m.Method {
		case "tools/call":
			tc, err := jsonrpc.ParseToolCall(m.Params)
			if err != nil {
				p.Audit.Log(audit.Event{Kind: "tool_call", Decision: "deny", Reason: "params: " + err.Error()})
				p.Logf("deny tools/call (%v)", err)
				p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeInvalidParams, "mcp-jail: "+err.Error()))
				return
			}
			pr.tool = tc.Name
			if !p.allowCall(m, tc) {
				return
			}
		case "prompts/get", "resources/read":
			if !p.allowUse(m) {
				return
			}
		}
		p.pmu.Lock()
		p.pending[m.IDKey()] = pr
		p.pmu.Unlock()
	}
	p.toServer(line)
}

// allowUse gates prompts/get and resources/read on their lock section.
// Returns false if the request was answered with an error.
func (p *Proxy) allowUse(m *jsonrpc.Message) bool {
	var params struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	_ = json.Unmarshal(m.Params, &params)
	what := params.Name + params.URI
	kind := "prompt"
	if m.Method == "resources/read" {
		kind = "resource"
	}
	if why := p.waitVerified(gate[m.Method]); why != "" {
		p.Audit.Log(audit.Event{Kind: kind, Tool: what, Decision: "deny", Reason: why})
		p.Logf("deny %s %s (%s)", m.Method, what, why)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: "+why))
		return false
	}
	p.Audit.Log(audit.Event{Kind: kind, Tool: what, Decision: "allow"})
	return true
}

// rules is the policy in force for tool decisions and asks.
func (p *Proxy) rules() *policy.Policy {
	if l := p.live.Load(); l != nil {
		return l
	}
	return p.Policy
}

// Reload takes the tools and ask sections of np into use for every call
// from now on. The rest of np is ignored: the sandbox and the lock were set
// up at start and cannot change under a running server. A policy for a
// different server name is refused.
func (p *Proxy) Reload(np *policy.Policy) error {
	if np == nil {
		return fmt.Errorf("reload: no policy")
	}
	if np.Name != p.Policy.Name {
		return fmt.Errorf("reload: policy is for %q, this jail is %q", np.Name, p.Policy.Name)
	}
	cp := *p.Policy
	cp.Tools = np.Tools
	cp.Ask = np.Ask
	p.live.Store(&cp)
	p.Audit.Log(audit.Event{Kind: "reload", Reason: fmt.Sprintf("tools.default=%s rules=%d", cp.Tools.Default, len(cp.Tools.Rules))})
	p.Logf("policy reloaded: tools.default=%s, %d rule(s)", cp.Tools.Default, len(cp.Tools.Rules))
	return nil
}

// allowCall applies tools policy. Returns false if the call was answered
// with an error and must not be forwarded.
func (p *Proxy) allowCall(m *jsonrpc.Message, tc jsonrpc.ToolCallParams) bool {
	pol := p.rules()
	var args json.RawMessage
	if pol.Audit.Args {
		args = tc.Arguments
	}
	if why := p.waitVerified(lock.Tools); why != "" {
		p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "deny", Reason: why, Args: args})
		p.Logf("deny tools/call %s (%s)", tc.Name, why)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: "+why))
		return false
	}
	d := pol.Decide(tc.Name)
	if d != policy.Deny {
		if err := pol.CheckArgs(tc.Name, tc.Arguments); err != nil {
			p.Audit.Log(audit.Event{Kind: "tool_call", Tool: tc.Name, Decision: "deny", Reason: "args: " + err.Error(), Args: args})
			p.Logf("deny tools/call %s (%v)", tc.Name, err)
			p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodePolicyDenied, "mcp-jail: tool "+tc.Name+" denied by policy: "+err.Error()))
			return false
		}
	}
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

// waitVerified blocks a use of list k (tools/call, prompts/get,
// resources/read) until that list has been checked against the lock.
// Returns "" when the call may proceed, otherwise the reason it must be
// denied. A call that arrives while the list is in flight waits for that
// response; a call before any list is refused, so a client cannot race the
// lock by calling before listing.
func (p *Proxy) waitVerified(k lock.Kind) string {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	st := p.sections[k]
	for {
		switch {
		case st.tainted && st.why != "":
			return st.why
		case st.tainted:
			return string(k) + " changed since last approval; run `mcp-jail approve " + p.Policy.Name + "`"
		case k == lock.Resources && p.sections[lock.ResourceTemplates].tainted:
			return "resource templates changed since last approval; run `mcp-jail approve " + p.Policy.Name + "`"
		case st.verified:
			return ""
		case st.inflight == 0:
			return gateMethod(k) + " before " + listMethod(k) + " was verified against the lock"
		}
		p.lcond.Wait()
	}
}

func gateMethod(k lock.Kind) string {
	for m, gk := range gate {
		if gk == k {
			return m
		}
	}
	return string(k)
}

func (p *Proxy) setLock(k lock.Kind, verified, tainted bool) {
	p.lmu.Lock()
	p.sections[k].verified, p.sections[k].tainted, p.sections[k].why = verified, tainted, ""
	p.lcond.Broadcast()
	p.lmu.Unlock()
}

// ask decides an `ask` call: on the controlling terminal when there is one,
// otherwise through the webhook when configured, otherwise no.
func (p *Proxy) ask(tc jsonrpc.ToolCallParams) (bool, string) {
	if p.tty == nil {
		path := p.TTYPath
		if path == "" {
			path = "/dev/tty"
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return p.askHeadless(tc)
		}
		p.tty = f
	}
	args := string(tc.Arguments)
	if len(args) > 400 {
		args = fmt.Sprintf("%s… (+%d bytes)", args[:400], len(args)-400)
	}
	_, _ = fmt.Fprintf(p.tty, "\n[mcp-jail] %s wants to call %s\n  args: %s\n  allow? [y/N] ", p.Policy.Name, printable(tc.Name), printable(args))
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

// fromServer handles one message coming from the jailed server. A line the
// proxy cannot parse is dropped, and so is a response to a request the
// proxy never forwarded: the only responses a server has any business
// sending are answers to what came through here, and an unmatched id is
// how a list response would dodge the lock.
func (p *Proxy) fromServer(line []byte) {
	m, err := jsonrpc.Parse(line)
	if err != nil {
		p.Audit.Log(audit.Event{Kind: "protocol", Decision: "blocked", Reason: "server: " + err.Error()})
		p.Logf("dropped server message: %v", err)
		return
	}
	if m.IsResponse() {
		p.pmu.Lock()
		pr, ok := p.pending[m.IDKey()]
		delete(p.pending, m.IDKey())
		p.pmu.Unlock()
		if !ok {
			p.Audit.Log(audit.Event{Kind: "protocol", Decision: "blocked", Reason: "server: response to unknown request id " + m.IDKey()})
			p.Logf("dropped server response to unknown request id %s", m.IDKey())
			// A list in flight will not get a usable answer from a server
			// that answers under the wrong id: refuse its uses instead of
			// parking them until the session ends.
			p.lmu.Lock()
			for k, st := range p.sections {
				if st.inflight > 0 && !st.verified {
					st.tainted, st.why = true, listMethod(k)+" answered under an unknown id; the server is not trusted"
				}
			}
			p.lcond.Broadcast()
			p.lmu.Unlock()
			return
		}
		{
			switch pr.method {
			case "tools/list", "prompts/list", "resources/list", "resources/templates/list":
				k := lock.KindOf(pr.method)
				ok := p.checkLock(k, m)
				p.lmu.Lock()
				p.sections[k].inflight--
				p.lcond.Broadcast()
				p.lmu.Unlock()
				if !ok {
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

// checkLock enforces rug-pull protection on a list response of kind k.
// Returns false when the response was replaced with an error.
func (p *Proxy) checkLock(k lock.Kind, m *jsonrpc.Message) bool {
	if !p.Policy.Lock.Enabled {
		return true
	}
	if m.Error != nil {
		return true // server refused to list; nothing to verify, nothing to use
	}
	sec, err := lock.ComputeResult(k, m.Result)
	if err != nil {
		// Fail closed: a list we cannot hash is a list we cannot trust.
		p.Logf("%s: cannot hash result: %v", listMethod(k), err)
		p.Audit.Log(audit.Event{Kind: "lock", Decision: "blocked", Reason: string(k) + ": " + err.Error()})
		p.setLock(k, false, true)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: cannot verify "+string(k)+" against the lock: "+err.Error()))
		return false
	}
	cur, err := lock.Load(p.Policy.Name)
	if err != nil {
		p.Logf("lock: %v", err)
		p.Audit.Log(audit.Event{Kind: "lock", Decision: "blocked", Reason: err.Error()})
		p.setLock(k, false, true)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: cannot read lock: "+err.Error()))
		return false
	}
	old := cur.Section(k)
	if old == nil {
		if _, err := lock.Record(p.Policy.Name, k, sec); err != nil {
			p.Logf("lock: save: %v", err)
		}
		p.Audit.Log(audit.Event{Kind: "lock", Decision: "created", Reason: string(k) + " " + lock.Short(sec.Hash)})
		p.Logf("lock: recorded %d %s (%s)", len(sec.Items), k, lock.Short(sec.Hash))
		p.setLock(k, true, false)
		return true
	}
	if old.Hash == sec.Hash {
		p.setLock(k, true, false)
		return true
	}
	d := lock.Compare(old.Items, sec.Items)
	_ = lock.SavePending(p.Policy.Name, k, sec)
	p.setLock(k, false, true)
	reason := string(k) + " " + d.String()
	p.Audit.Log(audit.Event{Kind: "lock", Decision: "blocked", Reason: reason})
	p.Logf("RUG-PULL: %s changed: %s", k, d)
	p.Logf("          inspect with `mcp-jail diff %s`, accept with `mcp-jail approve %s`", p.Policy.Name, p.Policy.Name)
	p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull,
		"mcp-jail: "+string(k)+" changed since last approval ("+d.String()+"); run `mcp-jail approve "+p.Policy.Name+"`"))
	return false
}

// printable replaces control characters (terminal escapes among them)
// with '?', so a tool name or argument chosen by a server or a client
// cannot redraw the ask prompt.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}
