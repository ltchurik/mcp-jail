package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
)

// reviewPoll is how often a headless review checks whether the section was
// approved (dashboard Approve or `mcp-jail approve` from another terminal).
const reviewPoll = 300 * time.Millisecond

// maxCatalog bounds how many items the terminal prompt lists in full.
const maxCatalog = 60

// reviewFirst handles a list of kind k that the lock has never recorded
// when lock.first is review: the list is saved as pending, shown to the
// operator, and recorded only on an explicit approve. Until then the list
// and its uses are refused (fail closed). Returns false when the response
// was replaced with an error.
func (p *Proxy) reviewFirst(k lock.Kind, m *jsonrpc.Message, sec lock.Section, items []json.RawMessage) bool {
	name := p.Policy.Name
	if err := lock.SavePending(name, k, sec); err != nil {
		p.Logf("lock: save pending: %v", err)
		p.Audit.Log(audit.Event{Kind: "lock", Decision: "blocked", Reason: string(k) + ": cannot save for review: " + err.Error()})
		p.setLock(k, false, true, nil)
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: cannot save "+string(k)+" for review: "+err.Error()))
		return false
	}
	p.Audit.Log(audit.Event{Kind: "lock", Decision: "review", Reason: fmt.Sprintf("%s first contact: %d item(s) await review", k, len(sec.Items))})
	p.Logf("lock: %d %s seen for the first time (%s); nothing is recorded until approved", len(sec.Items), k, lock.Short(sec.Hash))

	approved, how := p.reviewDecision(k, sec, items)
	if !approved {
		why := fmt.Sprintf("%s seen for the first time were not approved (%s); review with `mcp-jail diff %s`, accept with `mcp-jail approve %s`", k, how, name, name)
		p.Audit.Log(audit.Event{Kind: "lock", Decision: "blocked", Reason: string(k) + " first contact: not approved (" + how + ")"})
		p.Logf("lock: %s not approved (%s)", k, how)
		p.Logf("      inspect with `mcp-jail diff %s`, accept with `mcp-jail approve %s`", name, name)
		p.lmu.Lock()
		st := p.sections[k]
		st.verified, st.tainted, st.items = false, true, nil
		st.why = why
		p.lcond.Broadcast()
		p.lmu.Unlock()
		p.watch(k, "")
		p.toClient(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRugPull, "mcp-jail: "+why))
		return false
	}
	p.Audit.Log(audit.Event{Kind: "lock", Decision: "created", Reason: string(k) + " " + lock.Short(sec.Hash) + " (reviewed: " + how + ")"})
	p.Logf("lock: recorded %d %s (%s) after review (%s)", len(sec.Items), k, lock.Short(sec.Hash), how)
	p.setLock(k, true, false, sec.Items)
	return true
}

// reviewDecision obtains the approve for a first-contact list: on the
// terminal when there is one; otherwise, while a dashboard is attached, by
// waiting up to ask.timeout for the section to be approved out of band
// (the dashboard's Approve button or `mcp-jail approve`); otherwise it is a
// no at once. how names the source for the audit log.
func (p *Proxy) reviewDecision(k lock.Kind, sec lock.Section, items []json.RawMessage) (bool, string) {
	if p.openTTY() {
		return p.reviewOnTTY(k, sec, items)
	}
	if p.Asks == nil || !p.Asks.Attached() {
		return false, "no tty"
	}
	timeout := p.rules().Ask.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(reviewPoll)
		f, err := lock.Load(p.Policy.Name)
		if err != nil {
			return false, "cannot read lock: " + err.Error()
		}
		if s := f.Section(k); s != nil {
			if s.Hash == sec.Hash {
				return true, "dashboard"
			}
			return false, "a different " + string(k) + " list was approved meanwhile"
		}
	}
	return false, fmt.Sprintf("no answer within %s", timeout)
}

// reviewOnTTY prints the catalog and asks for a yes; a yes promotes the
// pending section into the lock.
func (p *Proxy) reviewOnTTY(k lock.Kind, sec lock.Section, items []json.RawMessage) (bool, string) {
	_, _ = fmt.Fprintf(p.tty, "\n[mcp-jail] %s: %d %s seen for the first time (%s)\n", p.Policy.Name, len(sec.Items), k, lock.Short(sec.Hash))
	for _, line := range catalog(k, items, sec.Lint, maxCatalog) {
		_, _ = fmt.Fprintf(p.tty, "  %s\n", printable(line))
	}
	if n := len(sec.Lint); n > 0 {
		_, _ = fmt.Fprintf(p.tty, "  %d lint finding(s) marked with !: look at them before you approve\n", n)
	}
	_, _ = fmt.Fprintf(p.tty, "  record these %s and allow their use? [y/N] ", k)
	ans, err := bufio.NewReader(p.tty).ReadString('\n')
	if err != nil {
		return false, "tty read error"
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans != "y" && ans != "yes" {
		return false, "user"
	}
	if _, err := lock.ApproveKind(p.Policy.Name, k); err != nil {
		p.Logf("lock: approve: %v", err)
		return false, "cannot record: " + err.Error()
	}
	return true, "tty"
}

// catalog renders one line per item: its key and the first line of its
// description, sorted by key, at most limit lines (plus one saying how many
// were left out). The lint findings of an item ("<key>: …" lines) follow
// it, marked with "!".
func catalog(k lock.Kind, items []json.RawMessage, lint []string, limit int) []string {
	type entry struct{ key, desc string }
	var es []entry
	for _, raw := range items {
		var v struct {
			Name        string `json:"name"`
			URI         string `json:"uri"`
			URITemplate string `json:"uriTemplate"`
			Description string `json:"description"`
		}
		if json.Unmarshal(raw, &v) != nil {
			continue
		}
		key := v.Name
		switch k {
		case lock.Resources:
			key = v.URI
		case lock.ResourceTemplates:
			key = v.URITemplate
		}
		desc := v.Description
		if i := strings.IndexAny(desc, "\r\n"); i >= 0 {
			desc = desc[:i]
		}
		if len(desc) > 100 {
			desc = desc[:100] + "…"
		}
		es = append(es, entry{key, desc})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].key < es[j].key })
	var out []string
	for i, e := range es {
		if i == limit {
			out = append(out, fmt.Sprintf("… and %d more", len(es)-limit))
			break
		}
		if e.desc == "" {
			out = append(out, e.key)
		} else {
			out = append(out, e.key+"  —  "+e.desc)
		}
		for _, l := range lint {
			if rest, ok := strings.CutPrefix(l, e.key+": "); ok {
				out = append(out, "  ! "+rest)
			}
		}
	}
	return out
}
