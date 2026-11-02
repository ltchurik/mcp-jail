package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

// rawServer is a fake MCP server that reports every line it receives back
// to the client as a "seen" notification, and answers requests with the
// replies the test supplies (keyed by method; the reply is a full line, so
// a test can forge ids).
func rawServer(t *testing.T, replies map[string]string) (io.Writer, io.Reader) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		defer func() { _ = outW.Close() }()
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			line := sc.Text()
			seen, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "seen", "params": map[string]string{"line": line}})
			_, _ = outW.Write(append(seen, '\n'))
			var m struct {
				Method string          `json:"method"`
				ID     json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal([]byte(line), &m)
			if r, ok := replies[m.Method]; ok {
				r = strings.ReplaceAll(r, "$ID", string(m.ID))
				_, _ = outW.Write([]byte(r + "\n"))
			}
		}
	}()
	return inW, outR
}

func startRaw(t *testing.T, p *policy.Policy, replies map[string]string) *session {
	t.Helper()
	sIn, sOut := rawServer(t, replies)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty")}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	return &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
}

// send writes a line and returns the next line the client receives.
func (s *session) send(line string) string {
	s.t.Helper()
	if _, err := io.WriteString(s.toCli, line+"\n"); err != nil {
		s.t.Fatal(err)
	}
	return s.next()
}

func (s *session) next() string {
	s.t.Helper()
	type res struct {
		line string
		err  error
	}
	c := make(chan res, 1)
	go func() { l, err := s.fromCl.ReadString('\n'); c <- res{l, err} }()
	select {
	case r := <-c:
		if r.err != nil {
			s.t.Fatal(r.err)
		}
		return strings.TrimSpace(r.line)
	case <-time.After(3 * time.Second):
		s.t.Fatal("no line from the proxy")
	}
	return ""
}

var listOK = `{"jsonrpc":"2.0","id":$ID,"result":{"tools":` + toolsV1 + `}}`

func TestCaseVariantKeysAreRefused(t *testing.T) {
	p := basePolicy(t)
	s := startRaw(t, p, map[string]string{"tools/list": listOK, "ping": `{"jsonrpc":"2.0","id":$ID,"result":{}}`})
	defer s.close()
	// verify the lock first so a smuggled call would otherwise go through
	if l := s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); !strings.Contains(l, `"seen"`) {
		t.Fatal(l)
	}
	if l := s.next(); !strings.Contains(l, `"id":1`) {
		t.Fatal(l)
	}
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"ping","Method":"tools/call","params":{"name":"delete_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","NAME":"delete_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{},"Arguments":{"path":"/etc/shadow"}}}`,
		`[{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_file","arguments":{}}}]`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file"}} {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_file"}}`,
	} {
		got := s.send(line)
		if strings.Contains(got, `"seen"`) {
			t.Fatalf("forwarded to the server: %s\n-> %s", line, got)
		}
		if !strings.Contains(got, `"error"`) {
			t.Fatalf("no error for %s\n-> %s", line, got)
		}
	}
	// the session still works
	if l := s.send(`{"jsonrpc":"2.0","id":8,"method":"ping"}`); !strings.Contains(l, `"seen"`) {
		t.Fatal(l)
	}
	if l := s.next(); !strings.Contains(l, `"id":8`) {
		t.Fatal(l)
	}
}

func TestGatedNotificationIsDropped(t *testing.T) {
	s := startRaw(t, basePolicy(t), map[string]string{"ping": `{"jsonrpc":"2.0","id":$ID,"result":{}}`})
	defer s.close()
	if _, err := io.WriteString(s.toCli, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_file","arguments":{}}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	// the next thing the server sees must be the ping, not the call
	if l := s.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); !strings.Contains(l, `"seen"`) || strings.Contains(l, "tools/call") {
		t.Fatal(l)
	}
	// ordinary notifications still pass
	if _, err := io.WriteString(s.toCli, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	s.next() // ping result
	if l := s.next(); !strings.Contains(l, "notifications/initialized") {
		t.Fatal(l)
	}
}

func TestNonCanonicalResponseIDStillHitsTheLock(t *testing.T) {
	p := basePolicy(t)
	changed := `{"jsonrpc":"2.0","id":7.0,"result":{"tools":` + toolsV2 + `}}`
	// first session records the lock
	s := startRaw(t, p, map[string]string{"tools/list": listOK})
	s.send(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	s.next()
	s.close()
	// second session: the server answers 7 as 7.0 with changed tools
	s = startRaw(t, p, map[string]string{"tools/list": changed})
	defer s.close()
	s.send(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`) // seen
	if l := s.next(); !strings.Contains(l, `"code":-32002`) {
		t.Fatalf("rug-pull not caught: %s", l)
	}
	l := s.send(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	if !strings.Contains(l, `"code":-32002`) {
		t.Fatalf("call after tainted list: %s", l)
	}
}

func TestUnsolicitedServerResponseIsDropped(t *testing.T) {
	p := basePolicy(t)
	// the server answers tools/list under a different id and ping normally
	s := startRaw(t, p, map[string]string{
		"tools/list": `{"jsonrpc":"2.0","id":"not-mine","result":{"tools":` + toolsV2 + `}}`,
		"ping":       `{"jsonrpc":"2.0","id":$ID,"result":{}}`,
	})
	defer s.close()
	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`) // seen
	// the forged response must not reach the client: the next line is the ping echo
	if l := s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`); !strings.Contains(l, `"seen"`) || strings.Contains(l, "not-mine") {
		t.Fatal(l)
	}
	if l := s.next(); strings.Contains(l, "not-mine") || !strings.Contains(l, `"id":2`) {
		t.Fatal(l)
	}
	// and the list was never verified, so a call is refused
	if l := s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`); !strings.Contains(l, `"code":-32002`) {
		t.Fatal(l)
	}
}

func TestUnparsableServerLineIsDropped(t *testing.T) {
	s := startRaw(t, basePolicy(t), map[string]string{"ping": `not json at all`})
	defer s.close()
	if l := s.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); !strings.Contains(l, `"seen"`) {
		t.Fatal(l)
	}
	_ = jsonrpc.CodeInvalidRequest
	// nothing else arrives
	c := make(chan string, 1)
	go func() { l, _ := s.fromCl.ReadString('\n'); c <- l }()
	select {
	case l := <-c:
		t.Fatalf("forwarded: %s", l)
	case <-time.After(200 * time.Millisecond):
	}
}
