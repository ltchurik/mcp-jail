package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

// askPolicy: everything is `ask`, no terminal, webhook at url.
func askPolicy(t *testing.T, url string, timeout time.Duration) *policy.Policy {
	p := basePolicy(t)
	p.Tools.Default = policy.Ask
	p.Tools.Rules = nil
	p.Ask.Webhook.URL = url
	p.Ask.Webhook.Timeout = timeout
	p.Ask.Webhook.Headers = map[string]string{"Authorization": "Bearer t0k"}
	return p
}

func startNoTTY(t *testing.T, p *policy.Policy) *session {
	t.Helper()
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty")}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	s.call(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`)
	return s
}

const callReq = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"}}}`

func TestWebhookAllow(t *testing.T) {
	var got webhookRequest
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"decision":"allow"}`)
	}))
	defer srv.Close()
	s := startNoTTY(t, askPolicy(t, srv.URL, 5*time.Second))
	defer s.close()
	if m := s.call(callReq); m.Error != nil {
		t.Fatalf("webhook allow: %+v", m.Error)
	}
	if got.Tool != "read_file" || got.Server != "test" || string(got.Arguments) != `{"path":"/x"}` || !strings.Contains(got.Text, "read_file") {
		t.Fatalf("payload: %+v", got)
	}
	if auth.Load() != "Bearer t0k" {
		t.Fatalf("headers not sent: %v", auth.Load())
	}
}

func TestWebhookDenies(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"deny": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"decision":"deny","reason":"nope"}`)
		},
		"slack-ok": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") },
		"status":   func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"garbage":  func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"decision":"ALLOW"}`) },
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			s := startNoTTY(t, askPolicy(t, srv.URL, 300*time.Millisecond))
			defer s.close()
			m := s.call(callReq)
			if m.Error == nil || m.Error.Code != jsonrpc.CodeAskRejected {
				t.Fatalf("%s: must be denied, got %s", name, m.Raw)
			}
			if !strings.Contains(m.Error.Message, "webhook") {
				t.Fatalf("%s: reason should mention the webhook: %s", name, m.Error.Message)
			}
		})
	}
	// unreachable endpoint
	s := startNoTTY(t, askPolicy(t, "http://127.0.0.1:1/", time.Second))
	defer s.close()
	if m := s.call(callReq); m.Error == nil || m.Error.Code != jsonrpc.CodeAskRejected {
		t.Fatalf("unreachable webhook must deny, got %s", m.Raw)
	}
}

func TestNoTTYNoWebhookDenies(t *testing.T) {
	p := askPolicy(t, "", 0)
	s := startNoTTY(t, p)
	defer s.close()
	m := s.call(callReq)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeAskRejected || !strings.Contains(m.Error.Message, "no tty") {
		t.Fatalf("got %s", m.Raw)
	}
}
