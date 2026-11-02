//go:build unix

package proxy

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
)

// fakeTTY returns a bidirectional file the proxy can use as its terminal
// and the other end the test reads prompts from and answers on.
func fakeTTY(t *testing.T) (jail, user *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	jail, user = os.NewFile(uintptr(fds[0]), "tty-jail"), os.NewFile(uintptr(fds[1]), "tty-user")
	t.Cleanup(func() { _ = user.Close() })
	return jail, user
}

func startWithTTY(t *testing.T, answer string) (*session, io.Reader) {
	t.Helper()
	p := reviewPolicy(t)
	jailTTY, userTTY := fakeTTY(t)
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, tty: jailTTY}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	go func() { _, _ = io.WriteString(userTTY, answer+"\n") }()
	return &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}, userTTY
}

func TestReviewOnTTYApproves(t *testing.T) {
	s, tty := startWithTTY(t, "y")
	defer s.close()
	m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if m.Error != nil {
		t.Fatalf("approved on the terminal, yet refused: %s", m.Raw)
	}
	// the prompt listed the catalog; it is complete once the question is out
	var prompt strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(prompt.String(), "[y/N]") {
		n, err := tty.Read(buf)
		prompt.Write(buf[:n])
		if err != nil {
			break
		}
	}
	for _, want := range []string{"2 tools seen for the first time", "delete_file  —  Delete", "read_file  —  Read", "record these tools"} {
		if !strings.Contains(prompt.String(), want) {
			t.Errorf("prompt lacks %q:\n%s", want, prompt.String())
		}
	}
	if m := s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`); m.Error != nil {
		t.Fatalf("call after tty approval refused: %s", m.Raw)
	}
	f, _ := lock.Load("test")
	if f == nil || len(f.Section(lock.Tools).Items) != 2 {
		t.Fatalf("lock after approve: %+v", f)
	}
	if pend, _ := lock.LoadPending("test"); pend != nil {
		t.Fatal("pending must be consumed by the approve")
	}
}

func TestReviewOnTTYRefuses(t *testing.T) {
	s, _ := startWithTTY(t, "n")
	defer s.close()
	m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(m.Error.Message, "(user)") {
		t.Fatalf("expected a refusal by the user, got %s", m.Raw)
	}
	if f, _ := lock.Load("test"); f != nil {
		t.Fatal("nothing may be recorded after a no")
	}
	if pend, _ := lock.LoadPending("test"); pend == nil {
		t.Fatal("pending must be kept so `mcp-jail diff` can show it")
	}
}
