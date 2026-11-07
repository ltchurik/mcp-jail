package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
	"github.com/ltchurik/mcp-jail/internal/registry"
	"github.com/ltchurik/mcp-jail/internal/sandbox"
)

// showDoc is what `mcp-jail show` prints: the jail as it is (a running
// server) or as it would be (a policy file), without starting anything.
type showDoc struct {
	Name     string     `json:"name"`
	Running  bool       `json:"running"`
	PID      int        `json:"pid,omitempty"`
	Since    *time.Time `json:"since,omitempty"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
	Policy   string     `json:"policy"`
	Command  []string   `json:"command,omitempty"`
	Server   string     `json:"server,omitempty"` // server.url for a remote server
	How      string     `json:"how,omitempty"`    // the sandbox a running jail reported at start

	Sandbox sandbox.Plan `json:"sandbox"`

	Tools struct {
		Default string         `json:"default"`
		Rules   map[string]int `json:"rules"` // decision -> count
	} `json:"tools"`
	Ask struct {
		Timeout string `json:"timeout"`
		Webhook string `json:"webhook,omitempty"`
	} `json:"ask"`
	Lock struct {
		Enabled  bool          `json:"enabled"`
		First    string        `json:"first"`
		Sections []showSection `json:"sections"`
		Pending  []string      `json:"pending,omitempty"`
	} `json:"lock"`
	Audit struct {
		Path string `json:"path"`
		Args bool   `json:"args"`
	} `json:"audit"`
}

type showSection struct {
	Kind    string    `json:"kind"`
	Count   int       `json:"count"`
	Hash    string    `json:"hash"`
	Updated time.Time `json:"updated"`
	// Lint lists the content findings the list had when it was approved.
	Lint []string `json:"lint,omitempty"`
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	pol := fs.String("policy", "", "policy file to explain (instead of a server name)")
	asJSON := fs.Bool("json", false, "print as JSON")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}
	var (
		doc showDoc
		p   *policy.Policy
		err error
	)
	switch {
	case *pol != "": // positional arguments are the server command (flag drops the "--")
		if p, err = policy.Load(*pol); err != nil {
			return err
		}
		doc.Policy, doc.Command = absPath(*pol), fs.Args()
		if p.Name == "" {
			switch {
			case p.Remote():
				p.Name = "remote"
			case len(doc.Command) > 0:
				p.Name = doc.Command[0]
			default:
				p.Name = "(unnamed)"
			}
		}
	case fs.NArg() == 1 && fs.Arg(0) != "":
		if p, err = loadKnown(fs.Arg(0), &doc); err != nil {
			return err
		}
	default:
		return errors.New("expected <name> or --policy FILE")
	}
	doc.Name = p.Name
	if p.Remote() {
		doc.Server = p.Server.URL
	}
	fill(&doc, p, sandbox.Explain(p, sandbox.Spec{Command: doc.Command, Protect: protectPaths(p, doc.Policy)}))
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	}
	return doc.write(os.Stdout)
}

// loadKnown finds a registered server (running first, then remembered) and
// loads its policy file as it is on disk now.
func loadKnown(name string, doc *showDoc) (*policy.Policy, error) {
	if _, err := registry.Prune(); err != nil {
		return nil, err
	}
	live, err := registry.List()
	if err != nil {
		return nil, err
	}
	for _, e := range live {
		if e.Name == name {
			since := e.StartedAt
			doc.Running, doc.PID, doc.Since = true, e.PID, &since
			doc.Policy, doc.Command, doc.How = e.Policy, e.Command, e.How
		}
	}
	if !doc.Running {
		known, err := registry.ListKnown()
		if err != nil {
			return nil, err
		}
		for _, k := range known {
			if k.Name == name {
				seen := k.LastSeen
				doc.LastSeen, doc.Policy, doc.Command = &seen, k.Policy, k.Command
			}
		}
	}
	if doc.Policy == "" {
		return nil, fmt.Errorf("no jail named %q has run here; use --policy FILE for a policy that never ran", name)
	}
	p, err := policy.Load(doc.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy of %s: %w", name, err)
	}
	if p.Name == "" {
		p.Name = name
	}
	return p, nil
}

func fill(doc *showDoc, p *policy.Policy, plan sandbox.Plan) {
	doc.Sandbox = plan
	doc.Tools.Default = string(p.Tools.Default)
	doc.Tools.Rules = map[string]int{}
	for _, r := range p.Tools.Rules {
		doc.Tools.Rules[string(r.Decision)]++
	}
	doc.Ask.Timeout = p.Ask.Timeout.String()
	doc.Ask.Webhook = p.Ask.Webhook.URL
	doc.Lock.Enabled, doc.Lock.First = p.Lock.Enabled, string(p.Lock.First)
	doc.Lock.Sections = []showSection{}
	if f, err := lock.Load(p.Name); err == nil && f != nil {
		for _, k := range lock.Kinds {
			if sec := f.Section(k); sec != nil {
				doc.Lock.Sections = append(doc.Lock.Sections, showSection{Kind: string(k), Count: len(sec.Items), Hash: lock.Short(sec.Hash), Updated: f.UpdatedAt, Lint: sec.Lint})
			}
		}
		if pend, err := lock.LoadPending(p.Name); err == nil && pend != nil {
			for _, k := range lock.Kinds {
				sec, ok := pend.Sections[k]
				if !ok {
					continue
				}
				if o := f.Section(k); o != nil {
					doc.Lock.Pending = append(doc.Lock.Pending, string(k)+" "+lock.Compare(o.Items, sec.Items).String()+lintCount(sec))
				} else {
					doc.Lock.Pending = append(doc.Lock.Pending, fmt.Sprintf("%s: %d item(s) seen for the first time, awaiting review%s", k, len(sec.Items), lintCount(sec)))
				}
			}
		}
	} else if pend, err := lock.LoadPending(p.Name); err == nil && pend != nil {
		for _, k := range lock.Kinds {
			if sec, ok := pend.Sections[k]; ok {
				doc.Lock.Pending = append(doc.Lock.Pending, fmt.Sprintf("%s: %d item(s) seen for the first time, awaiting review%s", k, len(sec.Items), lintCount(sec)))
			}
		}
	}
	doc.Audit.Path, doc.Audit.Args = p.Audit.Path, p.Audit.Args
}

func (d *showDoc) write(w io.Writer) error {
	pr := func(k, format string, args ...any) {
		_, _ = fmt.Fprintf(w, "%-12s %s\n", k+":", fmt.Sprintf(format, args...))
	}
	switch {
	case d.Running:
		pr("jail", "%s  running, pid %d, since %s", d.Name, d.PID, d.Since.Local().Format("2006-01-02 15:04:05"))
	case d.LastSeen != nil:
		pr("jail", "%s  not running, last started %s", d.Name, d.LastSeen.Local().Format("2006-01-02 15:04:05"))
	default:
		pr("jail", "%s  never ran here; this is what the policy would set up", d.Name)
	}
	pr("policy", "%s", d.Policy)
	switch {
	case d.Server != "":
		pr("server", "%s  (remote over Streamable HTTP: the jail is the only process talking to it)", d.Server)
	case len(d.Command) > 0:
		pr("command", "%s", strings.Join(d.Command, " "))
	default:
		pr("command", "(none given: pass it after -- to see the toolchain bind)")
	}
	s := d.Sandbox
	if d.How != "" {
		pr("sandbox", "%s  (as started)", d.How)
	} else {
		pr("sandbox", "%s", s.Kind)
	}
	if s.Kind != "remote" && s.Kind != "disabled" && s.Kind != "none" {
		if len(s.Base) > 0 {
			pr("  base", "%s", strings.Join(s.Base, " "))
		}
		if len(s.Hidden) > 0 {
			pr("  hidden", "%s", strings.Join(s.Hidden, " "))
		}
		pr("  read-only", "%s", orNone(s.ReadOnly))
		pr("  read-write", "%s", orNone(s.ReadWrite))
		if s.Tmp {
			pr("  tmp", "private")
		} else {
			pr("  tmp", "shared with the host")
		}
		if s.Toolchain != "" {
			pr("  toolchain", "%s  (read-only, for the server binary)", s.Toolchain)
		}
		if s.Cwd != "" {
			pr("  cwd", "%s  (read-only)", s.Cwd)
		}
		if len(s.Masked) > 0 {
			pr("  masked", "%s", strings.Join(s.Masked, " "))
		}
	}
	net := s.Network
	if len(s.Allow) > 0 {
		net += ": " + strings.Join(s.Allow, ", ")
	}
	switch {
	case s.Kind == "remote":
		net += "  (not applicable: the jail dials server.url only)"
	case s.Network == "all":
	case s.Hard:
		net += "  (enforced by the OS)"
	default:
		net += "  (cooperative: HTTP_PROXY only, nothing stops a server that ignores it)"
	}
	pr("network", "%s", net)
	if s.Kind != "remote" {
		pr("env", "%s", orNone(s.Env))
	}
	for _, e := range s.Exec {
		status := e.Status
		if e.Status == "sha256 mismatch" || e.Status == "missing" {
			status = strings.ToUpper(e.Status) + ": the jail will refuse to start"
		}
		pr("  exec", "%s  (%s)", e.Path, status)
	}
	for _, n := range s.Notes {
		pr("  note", "%s", n)
	}
	rules := []string{}
	for _, dec := range []string{"allow", "deny", "ask"} {
		if n := d.Tools.Rules[dec]; n > 0 {
			rules = append(rules, fmt.Sprintf("%d %s", n, dec))
		}
	}
	if len(rules) == 0 {
		rules = append(rules, "no rules")
	}
	pr("tools", "default %s, %s", d.Tools.Default, strings.Join(rules, ", "))
	ask := "timeout " + d.Ask.Timeout
	if d.Ask.Webhook != "" {
		ask += ", webhook " + d.Ask.Webhook
	}
	pr("ask", "%s", ask)
	lk := "off"
	if d.Lock.Enabled {
		lk = "on, first contact: " + d.Lock.First
		if len(d.Lock.Sections) == 0 {
			lk += "; nothing recorded yet"
		}
	}
	pr("lock", "%s", lk)
	for _, sec := range d.Lock.Sections {
		pr("  "+strings.ReplaceAll(sec.Kind, "_", " "), "%d items, %s, recorded %s%s", sec.Count, sec.Hash, sec.Updated.Local().Format("2006-01-02 15:04"), lintCount(lock.Section{Lint: sec.Lint}))
	}
	for _, p := range d.Lock.Pending {
		pr("  PENDING", "%s", p)
	}
	if d.Audit.Path == "" {
		pr("audit", "off")
	} else {
		args := "arguments not logged"
		if d.Audit.Args {
			args = "arguments logged"
		}
		pr("audit", "%s  (%s)", d.Audit.Path, args)
	}
	return nil
}

// lintCount renders ", N lint finding(s) (mcp-jail diff NAME)" for a
// section that had content findings when it was seen; "" otherwise.
func lintCount(sec lock.Section) string {
	if len(sec.Lint) == 0 {
		return ""
	}
	return fmt.Sprintf(", %d lint finding(s)", len(sec.Lint))
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	l = append([]string{}, l...)
	sort.Strings(l)
	return strings.Join(l, " ")
}
