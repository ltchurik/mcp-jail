package ui

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
)

// Report aggregates audit events over a time range: what ran, what was
// decided, which tools and hosts were hit, and what the lock saw.
type Report struct {
	Since     time.Time        `json:"since"`
	Until     time.Time        `json:"until"`
	Bucket    string           `json:"bucket"` // timeline bucket size, e.g. "1h"
	Total     int              `json:"total"`
	Decisions map[string]int   `json:"decisions"`
	Servers   []ServerReport   `json:"servers"`
	Tools     []ToolReport     `json:"tools"`
	Hosts     []HostReport     `json:"hosts"`
	Locks     []audit.Event    `json:"locks"`
	Errors    int              `json:"errors"`
	Reasons   []ReasonCount    `json:"reasons"`
	Timeline  []TimelineBucket `json:"timeline"`
	Skipped   int              `json:"skipped_lines,omitempty"`
	Files     []string         `json:"files"`
	Truncated bool             `json:"truncated,omitempty"`
}

// ServerReport is one server's totals.
type ServerReport struct {
	Name      string         `json:"name"`
	Total     int            `json:"total"`
	Calls     int            `json:"calls"`
	Decisions map[string]int `json:"decisions"`
	LastEvent time.Time      `json:"last_event"`
	Starts    int            `json:"starts"`
}

// ToolReport is one (server, tool) pair.
type ToolReport struct {
	Server   string  `json:"server"`
	Tool     string  `json:"tool"`
	Allow    int     `json:"allow"`
	Deny     int     `json:"deny"`
	AskAllow int     `json:"ask_allow"`
	AskDeny  int     `json:"ask_deny"`
	Total    int     `json:"total"`
	AvgMs    float64 `json:"avg_ms,omitempty"`
	Errors   int     `json:"errors,omitempty"`
}

// HostReport is one network destination.
type HostReport struct {
	Host    string   `json:"host"`
	Allowed int      `json:"allowed"`
	Blocked int      `json:"blocked"`
	Servers []string `json:"servers"`
}

// ReasonCount is a deny/block reason and how often it was given.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// TimelineBucket counts decisions in one time slot.
type TimelineBucket struct {
	Start   time.Time `json:"start"`
	Allow   int       `json:"allow"`
	Deny    int       `json:"deny"`
	Blocked int       `json:"blocked"`
	Ask     int       `json:"ask"`
}

// maxReportEvents bounds how many events one report reads.
const maxReportEvents = 200000

// BuildReport reads the audit files and aggregates events matching f. A
// zero f.Until means now; a zero f.Since means the earliest event.
func BuildReport(paths []string, f Filter, now time.Time) Report {
	evs, skipped := ReadEvents(paths, f, maxReportEvents)
	r := build(evs, f, now)
	r.Skipped = skipped
	r.Files = paths
	if r.Files == nil {
		r.Files = []string{}
	}
	r.Truncated = len(evs) == maxReportEvents
	return r
}

func build(evs []audit.Event, f Filter, now time.Time) Report {
	r := Report{Decisions: map[string]int{}, Servers: []ServerReport{}, Tools: []ToolReport{}, Hosts: []HostReport{}, Locks: []audit.Event{}, Reasons: []ReasonCount{}, Timeline: []TimelineBucket{}}
	r.Until = f.Until.UTC()
	if f.Until.IsZero() {
		r.Until = now.UTC()
	}
	r.Since = f.Since.UTC()
	if f.Since.IsZero() {
		if len(evs) > 0 {
			r.Since = evs[len(evs)-1].Time // ReadEvents returns newest first
		} else {
			r.Since = r.Until.Add(-24 * time.Hour)
		}
	}
	servers := map[string]*ServerReport{}
	tools := map[[2]string]*ToolReport{}
	hosts := map[string]*HostReport{}
	hostServers := map[string]map[string]bool{}
	reasons := map[string]int{}
	durations := map[[2]string][2]float64{} // sum, n

	for i := len(evs) - 1; i >= 0; i-- { // oldest first: a tool_result follows its tool_call
		e := &evs[i]
		r.Total++
		s := servers[e.Server]
		if s == nil {
			s = &ServerReport{Name: e.Server, Decisions: map[string]int{}}
			servers[e.Server] = s
		}
		s.Total++
		if e.Time.After(s.LastEvent) {
			s.LastEvent = e.Time
		}
		if e.Decision != "" {
			r.Decisions[e.Decision]++
			s.Decisions[e.Decision]++
		}
		if e.Error != "" {
			r.Errors++
		}
		switch e.Kind {
		case "start":
			s.Starts++
		case "tool_call":
			s.Calls++
			k := [2]string{e.Server, e.Tool}
			t := tools[k]
			if t == nil {
				t = &ToolReport{Server: e.Server, Tool: e.Tool}
				tools[k] = t
			}
			t.Total++
			switch e.Decision {
			case "allow":
				t.Allow++
			case "deny":
				t.Deny++
				if e.Reason != "" {
					reasons[e.Reason]++
				}
			case "ask_allow":
				t.AskAllow++
			case "ask_deny":
				t.AskDeny++
			}
		case "tool_result":
			k := [2]string{e.Server, e.Tool}
			if t := tools[k]; t != nil {
				if e.Error != "" {
					t.Errors++
				}
				if e.Duration != 0 {
					d := durations[k]
					durations[k] = [2]float64{d[0] + float64(e.Duration), d[1] + 1}
				}
			}
		case "net", "dns":
			if e.Host == "" {
				break
			}
			h := hosts[e.Host]
			if h == nil {
				h = &HostReport{Host: e.Host}
				hosts[e.Host] = h
				hostServers[e.Host] = map[string]bool{}
			}
			hostServers[e.Host][e.Server] = true
			if e.Decision == "blocked" {
				h.Blocked++
				reasons["network: "+e.Host]++
			} else {
				h.Allowed++
			}
		case "lock":
			r.Locks = append(r.Locks, *e)
		case "prompt", "resource":
			if e.Decision == "deny" && e.Reason != "" {
				reasons[e.Reason]++
			}
		}
	}
	for k, t := range tools {
		if d := durations[k]; d[1] > 0 {
			t.AvgMs = d[0] / d[1]
		}
		r.Tools = append(r.Tools, *t)
	}
	for _, s := range servers {
		r.Servers = append(r.Servers, *s)
	}
	for h, hr := range hosts {
		for s := range hostServers[h] {
			hr.Servers = append(hr.Servers, s)
		}
		sort.Strings(hr.Servers)
		r.Hosts = append(r.Hosts, *hr)
	}
	for reason, n := range reasons {
		r.Reasons = append(r.Reasons, ReasonCount{Reason: reason, Count: n})
	}
	sort.Slice(r.Servers, func(i, j int) bool { return r.Servers[i].Name < r.Servers[j].Name })
	sort.Slice(r.Tools, func(i, j int) bool {
		a, b := r.Tools[i], r.Tools[j]
		if da, db := a.Deny+a.AskDeny, b.Deny+b.AskDeny; da != db {
			return da > db
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		return a.Tool < b.Tool
	})
	sort.Slice(r.Hosts, func(i, j int) bool {
		a, b := r.Hosts[i], r.Hosts[j]
		if a.Blocked != b.Blocked {
			return a.Blocked > b.Blocked
		}
		if a.Allowed != b.Allowed {
			return a.Allowed > b.Allowed
		}
		return a.Host < b.Host
	})
	sort.Slice(r.Reasons, func(i, j int) bool {
		if r.Reasons[i].Count != r.Reasons[j].Count {
			return r.Reasons[i].Count > r.Reasons[j].Count
		}
		return r.Reasons[i].Reason < r.Reasons[j].Reason
	})
	sort.Slice(r.Locks, func(i, j int) bool { return r.Locks[i].Time.After(r.Locks[j].Time) })

	r.Timeline, r.Bucket = timeline(evs, r.Since, r.Until)
	return r
}

// bucketFor picks a slot width that yields a readable number of columns.
func bucketFor(span time.Duration) time.Duration {
	switch {
	case span <= 2*time.Hour:
		return 5 * time.Minute
	case span <= 48*time.Hour:
		return time.Hour
	case span <= 90*24*time.Hour:
		return 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

func timeline(evs []audit.Event, since, until time.Time) ([]TimelineBucket, string) {
	if !until.After(since) {
		return []TimelineBucket{}, ""
	}
	size := bucketFor(until.Sub(since))
	start := since.Truncate(size)
	n := int(until.Sub(start)/size) + 1
	if n > 400 { // never more than a few hundred columns
		size = until.Sub(start) / 400
		start = since
		n = 401
	}
	out := make([]TimelineBucket, n)
	for i := range out {
		out[i].Start = start.Add(time.Duration(i) * size)
	}
	for i := range evs {
		e := &evs[i]
		if e.Decision == "" {
			continue
		}
		idx := int(e.Time.Sub(start) / size)
		if idx < 0 || idx >= n {
			continue
		}
		b := &out[idx]
		switch e.Decision {
		case "allow":
			b.Allow++
		case "deny":
			b.Deny++
		case "blocked":
			b.Blocked++
		case "ask_allow", "ask_deny":
			b.Ask++
		}
	}
	return out, size.String()
}

// WriteCSV writes the per-tool table, then a blank line and the hosts table.
func (r Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	rows := [][]string{{"server", "tool", "total", "allow", "deny", "ask_allow", "ask_deny", "errors", "avg_ms"}}
	for _, t := range r.Tools {
		rows = append(rows, []string{cell(t.Server), cell(t.Tool), strconv.Itoa(t.Total), strconv.Itoa(t.Allow), strconv.Itoa(t.Deny), strconv.Itoa(t.AskAllow), strconv.Itoa(t.AskDeny), strconv.Itoa(t.Errors), fmtMs(t.AvgMs)})
	}
	rows = append(rows, []string{}, []string{"host", "allowed", "blocked", "servers"})
	for _, h := range r.Hosts {
		rows = append(rows, []string{cell(h.Host), strconv.Itoa(h.Allowed), strconv.Itoa(h.Blocked), cell(fmt.Sprint(h.Servers))})
	}
	if err := cw.WriteAll(rows); err != nil {
		return err
	}
	return cw.Error()
}

// cell neutralises spreadsheet formula injection: a value a server chose
// (tool or host name) that starts with =, +, -, @ or a tab/CR is prefixed
// with an apostrophe so Excel and friends show it as text.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func fmtMs(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// WriteText renders the report for a terminal.
func (r Report) WriteText(w io.Writer) error {
	_, err := io.WriteString(w, r.Text())
	return err
}

// Text renders the report for a terminal.
func (r Report) Text() string {
	var b strings.Builder
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(&b, format, a...) }
	p("mcp-jail report  %s → %s  (%s)\n", r.Since.Local().Format("2006-01-02 15:04"), r.Until.Local().Format("2006-01-02 15:04"), shortDur(r.Until.Sub(r.Since)))
	p("%d events from %d file(s)", r.Total, len(r.Files))
	if r.Skipped > 0 {
		p(", %d unparsable line(s) skipped", r.Skipped)
	}
	if r.Truncated {
		p(", truncated to the newest %d", maxReportEvents)
	}
	p("\n")
	if r.Total == 0 {
		return b.String()
	}
	p("decisions:")
	for _, k := range []string{"allow", "deny", "ask_allow", "ask_deny", "blocked", "created", "approved", "review", "warn"} {
		if n := r.Decisions[k]; n > 0 {
			p("  %s %d", k, n)
		}
	}
	p("\n")

	p("\n%-24s %6s %6s %6s %6s %8s  %s\n", "server", "calls", "allow", "deny", "ask", "blocked", "last event")
	for _, s := range r.Servers {
		p("%-24s %6d %6d %6d %6d %8d  %s\n", trunc(s.Name, 24), s.Calls, s.Decisions["allow"], s.Decisions["deny"], s.Decisions["ask_allow"]+s.Decisions["ask_deny"], s.Decisions["blocked"], s.LastEvent.Local().Format("2006-01-02 15:04:05"))
	}
	if len(r.Tools) > 0 {
		p("\n%-28s %-16s %6s %6s %6s %6s %7s\n", "tool", "server", "total", "allow", "deny", "ask", "avg ms")
		for _, t := range r.Tools {
			p("%-28s %-16s %6d %6d %6d %6d %7s\n", trunc(t.Tool, 28), trunc(t.Server, 16), t.Total, t.Allow, t.Deny+t.AskDeny, t.AskAllow+t.AskDeny, fmtMs(t.AvgMs))
		}
	}
	if len(r.Hosts) > 0 {
		p("\n%-40s %8s %8s  %s\n", "host", "allowed", "blocked", "servers")
		for _, h := range r.Hosts {
			p("%-40s %8d %8d  %s\n", trunc(h.Host, 40), h.Allowed, h.Blocked, joinMax(h.Servers, 3))
		}
	}
	if len(r.Reasons) > 0 {
		p("\ntop deny / block reasons:" + "\n")
		for i, rc := range r.Reasons {
			if i == 8 {
				break
			}
			p("  %5d  %s\n", rc.Count, trunc(rc.Reason, 100))
		}
	}
	if len(r.Locks) > 0 {
		p("\nlock events: %d\n", len(r.Locks))
		for i, e := range r.Locks {
			if i == 10 {
				p("  … %d more\n", len(r.Locks)-10)
				break
			}
			p("  %s  %-16s %-8s %s\n", e.Time.Local().Format("01-02 15:04:05"), trunc(e.Server, 16), e.Decision, trunc(e.Reason, 80))
		}
	}
	if r.Errors > 0 {
		p("\nevents with errors: %d\n", r.Errors)
	}
	return b.String()
}

// shortDur renders 24h0m0s as 24h, 1h30m0s as 1h30m, 7 days as 7d.
func shortDur(d time.Duration) string {
	d = d.Round(time.Minute)
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func joinMax(items []string, n int) string {
	if len(items) <= n {
		return fmt.Sprint(items)
	}
	return fmt.Sprintf("%v +%d", items[:n], len(items)-n)
}
