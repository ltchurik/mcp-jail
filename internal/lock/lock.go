// Package lock implements rug-pull protection: the server's tool, prompt and
// resource definitions are hashed on first run and any later change is
// refused until approved.
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
	"strings"
	"time"
)

// Kind is one locked list.
type Kind string

const (
	Tools             Kind = "tools"
	Prompts           Kind = "prompts"
	Resources         Kind = "resources"
	ResourceTemplates Kind = "resource_templates"
)

// Kinds in display order.
var Kinds = []Kind{Tools, Prompts, Resources, ResourceTemplates}

// KindOf maps a list method to its kind; "" for anything else.
func KindOf(method string) Kind {
	switch method {
	case "tools/list":
		return Tools
	case "prompts/list":
		return Prompts
	case "resources/list":
		return Resources
	case "resources/templates/list":
		return ResourceTemplates
	}
	return ""
}

// keyField is the JSON field that identifies an item of each kind.
func keyField(k Kind) string {
	switch k {
	case Resources:
		return "uri"
	case ResourceTemplates:
		return "uriTemplate"
	}
	return "name"
}

// listField is the JSON array holding the items in a list response.
func listField(k Kind) string {
	if k == ResourceTemplates {
		return "resourceTemplates"
	}
	return string(k)
}

// Section is one locked list: an overall hash and a per-item hash. Lint
// keeps the content findings (package scan) the list had when it was seen,
// one line per finding, so that diff, show and the dashboard can repeat
// them without the items themselves.
type Section struct {
	Hash  string            `json:"hash"`
	Items map[string]string `json:"items"`
	Lint  []string          `json:"lint,omitempty"`
}

// File is the on-disk lock. Tools keep their original top-level fields so
// locks written by v0.1 still load; the other kinds live in Sections.
type File struct {
	Name      string            `json:"name"`
	Hash      string            `json:"hash,omitempty"`
	Tools     map[string]string `json:"tools,omitempty"`
	ToolsLint []string          `json:"tools_lint,omitempty"`
	Sections  map[Kind]Section  `json:"sections,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Section returns the locked section for k, or nil when never recorded.
func (f *File) Section(k Kind) *Section {
	if f == nil {
		return nil
	}
	if k == Tools {
		if f.Tools == nil {
			return nil
		}
		return &Section{Hash: f.Hash, Items: f.Tools, Lint: f.ToolsLint}
	}
	s, ok := f.Sections[k]
	if !ok {
		return nil
	}
	return &s
}

// Set records a section.
func (f *File) Set(k Kind, s Section) {
	if k == Tools {
		f.Hash, f.Tools, f.ToolsLint = s.Hash, s.Items, s.Lint
		return
	}
	if f.Sections == nil {
		f.Sections = map[Kind]Section{}
	}
	f.Sections[k] = s
}

// Pending holds unapproved sections, written next to the lock when a
// mismatch is seen, so that `mcp-jail diff` and `approve` can act on them.
type Pending struct {
	Name     string           `json:"name"`
	Sections map[Kind]Section `json:"sections"`
	SeenAt   time.Time        `json:"seen_at"`

	// v0.1 wrote tools at the top level.
	Hash  string            `json:"hash,omitempty"`
	Tools map[string]string `json:"tools,omitempty"`
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

// Compute hashes a list of items of kind k. Each item is hashed from its
// canonical JSON (sorted keys); the section hash covers the sorted per-item
// hashes.
func Compute(k Kind, items []json.RawMessage) (Section, error) {
	per := make(map[string]string, len(items))
	for _, raw := range items {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			return Section{}, err
		}
		key, _ := v[keyField(k)].(string)
		if key == "" {
			return Section{}, fmt.Errorf("%s item without %s", k, keyField(k))
		}
		if _, dup := per[key]; dup {
			// two definitions under one name: a client may use either, so
			// neither can be trusted
			return Section{}, fmt.Errorf("%s: duplicate %s %q", k, keyField(k), key)
		}
		canon, err := json.Marshal(v) // map keys are sorted by encoding/json
		if err != nil {
			return Section{}, err
		}
		sum := sha256.Sum256(canon)
		per[key] = hex.EncodeToString(sum[:])
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
	return Section{Hash: hex.EncodeToString(h.Sum(nil)), Items: per}, nil
}

// Page is one page of a list result: its items and the cursor for the
// next page ("" on the last one).
type Page struct {
	Items []json.RawMessage
	Next  string
}

// ParsePage reads the items and nextCursor of a raw list result of kind k.
func ParsePage(k Kind, result json.RawMessage) (Page, error) {
	var res map[string]json.RawMessage
	if err := json.Unmarshal(result, &res); err != nil {
		return Page{}, err
	}
	var pg Page
	if raw, ok := res[listField(k)]; ok {
		if err := json.Unmarshal(raw, &pg.Items); err != nil {
			return Page{}, err
		}
	}
	if raw, ok := res["nextCursor"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &pg.Next); err != nil {
			return Page{}, fmt.Errorf("nextCursor: %w", err)
		}
	}
	return pg, nil
}

// ComputeResult hashes the list found in a raw list result of kind k,
// treating it as the whole list (see ParsePage for paged results).
func ComputeResult(k Kind, result json.RawMessage) (Section, error) {
	pg, err := ParsePage(k, result)
	if err != nil {
		return Section{}, err
	}
	return Compute(k, pg.Items)
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

// Record stores section k for name: creates the lock when there is none,
// otherwise adds or replaces that section only.
func Record(name string, k Kind, s Section) (*File, error) {
	f, err := Load(name)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if f == nil {
		f = &File{Name: name, CreatedAt: now}
	}
	f.Set(k, s)
	f.UpdatedAt = now
	return f, Save(f)
}

// SavePending records an unapproved section, keeping other pending sections.
func SavePending(name string, k Kind, s Section) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	p, err := LoadPending(name)
	if err != nil {
		return err
	}
	if p == nil {
		p = &Pending{Name: name, Sections: map[Kind]Section{}}
	}
	p.Sections[k] = s
	p.SeenAt = time.Now().UTC()
	return writeAtomic(pending(name), p)
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
	if p.Sections == nil {
		p.Sections = map[Kind]Section{}
	}
	if p.Tools != nil { // v0.1 layout
		p.Sections[Tools] = Section{Hash: p.Hash, Items: p.Tools}
		p.Hash, p.Tools = "", nil
	}
	return &p, nil
}

// Approve promotes every pending section into the lock and removes the
// pending record.
func Approve(name string) (*File, error) {
	return approve(name, "")
}

// ApproveKind promotes only the pending section k into the lock; other
// pending sections stay pending.
func ApproveKind(name string, k Kind) (*File, error) {
	if k == "" {
		return nil, errors.New("approve: no kind")
	}
	return approve(name, k)
}

func approve(name string, only Kind) (*File, error) {
	p, err := LoadPending(name)
	if err != nil {
		return nil, err
	}
	if p == nil || len(p.Sections) == 0 {
		return nil, fmt.Errorf("nothing pending for %q", name)
	}
	if only != "" {
		if _, ok := p.Sections[only]; !ok {
			return nil, fmt.Errorf("nothing pending for %q %s", name, only)
		}
	}
	f, err := Load(name)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if f == nil {
		f = &File{Name: name, CreatedAt: now}
	}
	for k, s := range p.Sections {
		if only == "" || k == only {
			f.Set(k, s)
			delete(p.Sections, k)
		}
	}
	f.UpdatedAt = now
	if err := Save(f); err != nil {
		return nil, err
	}
	if len(p.Sections) == 0 {
		_ = os.Remove(pending(name))
		return f, nil
	}
	return f, writeAtomic(pending(name), p)
}

// OtherTools maps every tool name recorded in the locks of servers other
// than exclude to the server that owns it, for the shadowing rule of
// package scan. Unreadable locks are skipped: this is a hint, not a gate.
func OtherTools(exclude string) map[string]string {
	ents, err := os.ReadDir(Dir())
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".lock.json")
		if !ok || name == exclude {
			continue
		}
		f, err := Load(name)
		if err != nil || f == nil {
			continue
		}
		for n := range f.Tools {
			if _, dup := out[n]; !dup {
				out[n] = name
			}
		}
	}
	return out
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

// Diff describes how items changed between two per-item hash maps.
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

func (d Diff) String() string {
	return fmt.Sprintf("added=%v removed=%v changed=%v", d.Added, d.Removed, d.Changed)
}

// Short returns the first 12 hex digits of a hash for log lines.
func Short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

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
