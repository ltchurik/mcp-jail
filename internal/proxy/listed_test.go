package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

// pagedServer serves tools/list in two pages: the first (no cursor) with
// read_file and nextCursor "p2", the second (cursor "p2") with delete_file.
func pagedServer(t *testing.T) (io.Writer, io.Reader) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		defer func() { _ = outW.Close() }()
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			m, err := jsonrpc.Parse(sc.Bytes())
			if err != nil || !m.IsRequest() {
				continue
			}
			res := `{}`
			switch m.Method {
			case "tools/list":
				var lp struct {
					Cursor string `json:"cursor"`
				}
				_ = json.Unmarshal(m.Params, &lp)
				if lp.Cursor == "" {
					res = `{"tools":[{"name":"read_file","description":"Read"}],"nextCursor":"p2"}`
				} else {
					res = `{"tools":[{"name":"delete_file","description":"Delete"}]}`
				}
			case "tools/call":
				res = `{"content":[{"type":"text","text":"ok"}]}`
			}
			b, _ := json.Marshal(jsonrpc.Message{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(res)})
			_, _ = outW.Write(append(b, '\n'))
		}
	}()
	return inW, outR
}

func startPaged(t *testing.T, p *policy.Policy) *session {
	t.Helper()
	sIn, sOut := pagedServer(t)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty")}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	return &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
}

func TestCallToUnlistedToolIsRefused(t *testing.T) {
	p := basePolicy(t)
	p.Tools.Default = policy.Allow
	s := start(t, p, toolsV1)
	defer s.close()
	s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if r := s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`); r.Error != nil {
		t.Fatalf("listed tool: %v", r.Error)
	}
	r := s.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ghost","arguments":{}}}`)
	if r.Error == nil || r.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(r.Error.Message, `tool "ghost" is not in the tools/list`) {
		t.Fatalf("unlisted tool: %+v", r.Error)
	}
}

func TestUnlistedPromptIsRefused(t *testing.T) {
	p := basePolicy(t)
	s := startWith(t, p, toolsV1, map[string]string{"prompts/list": `{"prompts":[{"name":"summarize"}]}`})
	defer s.close()
	s.call(`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	if r := s.call(`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"summarize"}}`); r.Error != nil {
		t.Fatalf("listed prompt: %v", r.Error)
	}
	r := s.call(`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"other"}}`)
	if r.Error == nil || r.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(r.Error.Message, `prompt "other" is not in the prompts/list`) {
		t.Fatalf("unlisted prompt: %+v", r.Error)
	}
}

func TestLockOffDoesNotCheckListing(t *testing.T) {
	p := basePolicy(t)
	p.Lock.Enabled = false
	p.Tools.Default = policy.Allow
	s := start(t, p, toolsV1)
	defer s.close()
	if r := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ghost","arguments":{}}}`); r.Error != nil {
		t.Fatalf("lock off: %v", r.Error)
	}
}

func TestPagedListIsVerifiedWhole(t *testing.T) {
	p := basePolicy(t)
	p.Tools.Default = policy.Allow
	s := startPaged(t, p)
	r := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if r.Error != nil || !strings.Contains(string(r.Result), `"nextCursor":"p2"`) {
		t.Fatalf("page 1: %s %v", r.Result, r.Error)
	}
	// between pages: no verified list yet, so no call (and no hang)
	r = s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	if r.Error == nil || r.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(r.Error.Message, "still being paged") {
		t.Fatalf("call between pages: %+v", r.Error)
	}
	r = s.call(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"p2"}}`)
	if r.Error != nil || !strings.Contains(string(r.Result), "delete_file") {
		t.Fatalf("page 2: %s %v", r.Result, r.Error)
	}
	for _, tool := range []string{"read_file", "delete_file"} {
		if r := s.call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`); r.Error != nil {
			t.Fatalf("%s after paging: %v", tool, r.Error)
		}
	}
	f, err := lock.Load("test")
	if err != nil || f == nil || len(f.Tools) != 2 {
		t.Fatalf("lock should hold both pages: %+v %v", f, err)
	}
	s.close()

	// A second session pages the same list: same hash, verified again.
	s2 := startPaged(t, p)
	defer s2.close()
	s2.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	s2.call(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"p2"}}`)
	if r := s2.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_file","arguments":{}}}`); r.Error != nil {
		t.Fatalf("second session: %v", r.Error)
	}
}

func TestUnknownCursorIsRefused(t *testing.T) {
	p := basePolicy(t)
	s := startPaged(t, p)
	defer s.close()
	r := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"bogus"}}`)
	if r.Error == nil || r.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(r.Error.Message, "never issued") {
		t.Fatalf("bogus cursor: %+v", r.Error)
	}
	r = s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	if r.Error == nil || r.Error.Code != jsonrpc.CodeRugPull {
		t.Fatalf("call after a refused listing: %+v", r.Error)
	}
	// starting over without a cursor recovers
	s.call(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	s.call(`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"cursor":"p2"}}`)
	if r := s.call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`); r.Error != nil {
		t.Fatalf("after a fresh listing: %v", r.Error)
	}
}
