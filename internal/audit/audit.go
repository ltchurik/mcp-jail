// Package audit writes a JSONL audit log of everything mcp-jail decides.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time     time.Time       `json:"ts"`
	Server   string          `json:"server"`
	Kind     string          `json:"kind"` // tool_call, tool_result, lock, net, start, exit
	Tool     string          `json:"tool,omitempty"`
	Decision string          `json:"decision,omitempty"` // allow, deny, ask_allow, ask_deny, blocked
	Reason   string          `json:"reason,omitempty"`
	Host     string          `json:"host,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	Duration time.Duration   `json:"duration_ms,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Logger appends events to a file. A nil *Logger is a no-op.
type Logger struct {
	mu     sync.Mutex
	f      *os.File
	server string
}

// Open creates the logger; empty path returns a no-op logger.
func Open(path, server string) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Never follow a symlink: a server that can write where the log lives
	// must not be able to point it at another file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|noFollow, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		if err == nil {
			err = fmt.Errorf("%s: not a regular file", path)
		}
		return nil, err
	}
	return &Logger{f: f, server: server}, nil
}

// Log writes one event.
func (l *Logger) Log(e Event) {
	if l == nil {
		return
	}
	e.Time = time.Now().UTC()
	e.Server = l.server
	if e.Duration != 0 {
		e.Duration = e.Duration / time.Millisecond
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

// Close flushes and closes the file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}
