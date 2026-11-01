// Package lock implements rug-pull protection: the server's tool definitions
// are hashed on first run and any later change is refused until approved.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// File is the on-disk lock.
type File struct {
	Name      string            `json:"name"`
	Hash      string            `json:"hash"`
	Tools     map[string]string `json:"tools"` // tool name -> per-tool hash
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Pending is written next to the lock when a mismatch is seen, so that
// `mcp-jail approve` can show a diff and promote it.
type Pending struct {
	Name   string            `json:"name"`
	Hash   string            `json:"hash"`
	Tools  map[string]string `json:"tools"`
	SeenAt time.Time         `json:"seen_at"`
}

// Dir returns the lock directory, honouring $XDG_CONFIG_HOME.
func Dir() string {
	if d := os.Getenv("MCP_JAIL_HOME"); d != "" {
		return d
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		h, _ := os.UserHomeDir()
		base = filepath.Join(h, ".config")
	}
	return filepath.Join(base, "mcp-jail", "locks")
}

func path(name string) string    { return filepath.Join(Dir(), name+".lock.json") }
func pending(name string) string { return filepath.Join(Dir(), name+".pending.json") }

// Compute hashes a tools/list result. Each tool is hashed from its canonical
// JSON (sorted keys), then the overall hash covers the sorted per-tool hashes.
func Compute(tools []json.RawMessage) (string, map[string]string, error) {
	per := make(map[string]string, len(tools))
	for _, raw := range tools {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", nil, err
		}
		name, _ := v["name"].(string)
		if name == "" {
			return "", nil, errors.New("tool without name")
		}
		canon, err := json.Marshal(v) // map keys are sorted by encoding/json
		if err != nil {
			return "", nil, err
		}
		sum := sha256.Sum256(canon)
		per[name] = hex.EncodeToString(sum[:])
	}
	names := make([]string, 0, len(per))
	for n := range per {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(per[n]))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), per, nil
}

// Load reads the lock for name. Returns (nil, nil) when none exists.
func Load(name string) (*File, error) {
	b, err := os.ReadFile(path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("corrupt lock %s: %w", path(name), err)
	}
	return &f, nil
}

// Save writes the lock atomically.
func Save(f *File) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	return writeAtomic(path(f.Name), f)
}

// SavePending records an unapproved tool set.
func SavePending(p *Pending) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	return writeAtomic(pending(p.Name), p)
}

// LoadPending reads a pending record; (nil, nil) when none.
func LoadPending(name string) (*Pending, error) {
	b, err := os.ReadFile(pending(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Approve promotes the pending record to the lock and removes it.
func Approve(name string) (*File, error) {
	p, err := LoadPending(name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("nothing pending for %q", name)
	}
	old, _ := Load(name)
	now := time.Now().UTC()
	f := &File{Name: name, Hash: p.Hash, Tools: p.Tools, CreatedAt: now, UpdatedAt: now}
	if old != nil {
		f.CreatedAt = old.CreatedAt
	}
	if err := Save(f); err != nil {
		return nil, err
	}
	_ = os.Remove(pending(name))
	return f, nil
}

// Reset deletes lock and pending for name.
func Reset(name string) error {
	_ = os.Remove(pending(name))
	err := os.Remove(path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Diff describes how tools changed between two per-tool hash maps.
type Diff struct {
	Added, Removed, Changed []string
}

// Compare returns the diff from old to new.
func Compare(old, new map[string]string) Diff {
	var d Diff
	for n, h := range new {
		oh, ok := old[n]
		switch {
		case !ok:
			d.Added = append(d.Added, n)
		case oh != h:
			d.Changed = append(d.Changed, n)
		}
	}
	for n := range old {
		if _, ok := new[n]; !ok {
			d.Removed = append(d.Removed, n)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	return d
}

func (d Diff) Empty() bool { return len(d.Added)+len(d.Removed)+len(d.Changed) == 0 }

func writeAtomic(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
