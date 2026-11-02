// Package registry records which jails are running so that `mcp-jail ui`
// and `mcp-jail ps` can find them and their audit logs.
//
// Each `mcp-jail run` writes <lock.Dir()>/../run/<name>.<pid>.json on start
// and removes it on exit. A file whose pid is gone is stale: readers skip it
// and `Prune` deletes it. The registry is advisory; the jail itself never
// depends on it (fail closed is enforced by the proxy, not here).
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/lock"
)

// Entry describes one running jail.
type Entry struct {
	Name      string    `json:"name"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Policy    string    `json:"policy"`            // absolute path of the policy file
	Audit     string    `json:"audit"`             // absolute path of the audit log, "" if disabled
	Command   []string  `json:"command"`           // the server command
	How       string    `json:"how"`               // sandbox description, e.g. "bwrap", "sandbox-exec", "no sandbox"
	Network   string    `json:"network"`           // network.mode
	Default   string    `json:"default"`           // tools.default
	Lock      bool      `json:"lock"`              // lock.enabled
	Hostname  string    `json:"hostname"`          // informational
	Control   string    `json:"control,omitempty"` // control socket path, "" when unavailable
	path      string
}

// Dir returns the registry directory: next to the lock directory, or
// inside $MCP_JAIL_HOME when that is set (so a custom home stays
// self-contained).
func Dir() string {
	if h := os.Getenv("MCP_JAIL_HOME"); h != "" {
		return filepath.Join(h, "run")
	}
	return filepath.Join(filepath.Dir(lock.Dir()), "run")
}

// Register writes the entry for the current process. It returns a function
// that removes it.
func Register(e Entry) (func(), error) {
	if e.Name == "" {
		return nil, errors.New("registry: empty name")
	}
	if e.PID == 0 {
		e.PID = os.Getpid()
	}
	if e.StartedAt.IsZero() {
		e.StartedAt = time.Now().UTC()
	}
	e.Hostname, _ = os.Hostname()
	e.Command = Redact(e.Command)
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	p := filepath.Join(Dir(), fmt.Sprintf("%s.%d.json", safe(e.Name), e.PID))
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	remember(e)
	return func() { _ = os.Remove(p) }, nil
}

// Known is a server that ran at least once: where its policy and audit log
// are, so the dashboard can show its history after it exits.
type Known struct {
	Name     string    `json:"name"`
	Policy   string    `json:"policy"`
	Audit    string    `json:"audit"`
	Command  []string  `json:"command"`
	LastSeen time.Time `json:"last_seen"`
}

func knownDir() string { return filepath.Join(Dir(), "known") }

func remember(e Entry) {
	if err := os.MkdirAll(knownDir(), 0o700); err != nil {
		return
	}
	k := Known{Name: e.Name, Policy: e.Policy, Audit: e.Audit, Command: e.Command, LastSeen: e.StartedAt}
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(knownDir(), safe(e.Name)+".json"), b, 0o600)
}

// ListKnown returns every server that ever registered, by name.
func ListKnown() ([]Known, error) {
	ents, err := os.ReadDir(knownDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	var out []Known
	for _, d := range ents {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(knownDir(), d.Name()))
		if err != nil {
			continue
		}
		var k Known
		if json.Unmarshal(b, &k) == nil && k.Name != "" {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Forget removes a known server (not a running one).
func Forget(name string) error {
	err := os.Remove(filepath.Join(knownDir(), safe(name)+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// List returns the live entries, oldest first. Stale entries (pid gone) are
// skipped; use Prune to delete them.
func List() ([]Entry, error) {
	all, err := read()
	if err != nil {
		return nil, err
	}
	var live []Entry
	for _, e := range all {
		if alive(e.PID) {
			live = append(live, e)
		}
	}
	return live, nil
}

// Prune removes entries whose process is gone and returns how many.
func Prune() (int, error) {
	all, err := read()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range all {
		if !alive(e.PID) {
			if os.Remove(e.path) == nil {
				n++
			}
		}
	}
	return n, nil
}

func read() ([]Entry, error) {
	ents, err := os.ReadDir(Dir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	var out []Entry
	for _, d := range ents {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			continue
		}
		p := filepath.Join(Dir(), d.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(b, &e) != nil || e.Name == "" || e.PID <= 0 {
			// not ours or corrupt: treat as stale so Prune can clear it
			e = Entry{PID: -1}
		}
		e.path = p
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

func safe(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "server"
	}
	return b.String()
}
