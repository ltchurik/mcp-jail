// Package ui serves the local dashboard: running jails, audit events and
// pending lock changes, read from the registry, the lock directory and the
// JSONL audit logs.
//
// The server binds to the loopback interface only and every request needs
// the one-time token printed at start, either as ?token= on the first visit
// (which sets a cookie) or as an Authorization: Bearer header. Mutating
// endpoints additionally require a same-origin fetch. Nothing here weakens
// the jail: the dashboard reads state; the proxy keeps enforcing the policy
// whether or not the dashboard runs.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/registry"
)

//go:embed static
var static embed.FS

const cookieName = "mcp_jail_ui"

// Server is the dashboard. Zero value is not usable; call New.
type Server struct {
	token   string
	version string
	// Extra audit files to show besides the ones registered by `run`.
	extra []string
	// PollInterval is how often the live stream looks for new audit lines.
	PollInterval time.Duration
	// Now is overridable for tests.
	Now func() time.Time
	// Logf receives one line per action taken from the page; nil discards.
	Logf func(format string, args ...any)
	mux  *http.ServeMux
}

// NewToken returns a random URL-safe token.
func NewToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// New builds a server guarded by token. extra lists additional audit files.
func New(token, version string, extra []string) (*Server, error) {
	if len(token) < 16 {
		return nil, errors.New("ui: token too short")
	}
	var abs []string
	for _, e := range extra {
		a, err := filepath.Abs(e)
		if err != nil {
			return nil, err
		}
		abs = append(abs, a)
	}
	s := &Server{token: token, version: version, extra: abs, PollInterval: 500 * time.Millisecond, Now: time.Now, Logf: func(string, ...any) {}}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", s.requireAuth(http.FileServerFS(mustSub(static, "static")))))
	s.mux.Handle("GET /api/state", s.requireAuth(http.HandlerFunc(s.handleState)))
	s.mux.Handle("GET /api/events", s.requireAuth(http.HandlerFunc(s.handleEvents)))
	s.mux.Handle("GET /api/stream", s.requireAuth(http.HandlerFunc(s.handleStream)))
	s.mux.Handle("GET /api/report", s.requireAuth(http.HandlerFunc(s.handleReport)))
	s.mux.Handle("POST /api/servers/{name}/approve", s.requireMutation(http.HandlerFunc(s.handleApprove)))
	return s, nil
}

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// Handler returns the HTTP handler; the loopback check runs on every request.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			// DNS rebinding: a page on evil.example resolving to 127.0.0.1
			// would carry its own Host header.
			http.Error(w, "mcp-jail ui answers only on localhost", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		s.mux.ServeHTTP(w, r)
	})
}

// Listen binds addr, which must be a loopback address, and returns the
// listener so the caller can print the URL before serving.
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ui: --listen %q: %w", addr, err)
	}
	if !loopbackHost(host) {
		return nil, fmt.Errorf("ui: refusing to listen on %q: the dashboard binds to localhost only", addr)
	}
	return net.Listen("tcp", addr)
}

// URL is the address to open in a browser, token included.
func (s *Server) URL(l net.Listener) string {
	host, port, _ := net.SplitHostPort(l.Addr().String())
	if host == "::1" {
		host = "[::1]"
	}
	return fmt.Sprintf("http://%s:%s/?token=%s", host, port, s.token)
}

func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) authorized(r *http.Request) bool {
	var got string
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		got = strings.TrimPrefix(h, "Bearer ")
	} else if c, err := r.Cookie(cookieName); err == nil {
		got = c.Value
	}
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unauthorized: open the URL printed by `mcp-jail ui`", http.StatusUnauthorized)
			return
		}
		// A cross-site page cannot read the response thanks to SameSite, but
		// refuse the request outright when the browser tells us it is one.
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// mutationHeader must accompany every state-changing request. A browser
// only sends custom headers on fetch() from a page that passed CORS, and
// this server sends no CORS headers, so a cross-site page cannot forge it.
const mutationHeader = "X-Mcp-Jail"

// requireMutation is requireAuth plus the same-origin proof for writes:
// the custom header, and when the browser states the fetch site, it must be
// same-origin (a form post from another site says cross-site; a direct
// tool such as curl says nothing and is accepted with the bearer token).
func (s *Server) requireMutation(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(mutationHeader) == "" {
			http.Error(w, "missing "+mutationHeader+" header", http.StatusForbidden)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r.Host) {
			http.Error(w, "origin mismatch", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func sameOrigin(origin, host string) bool {
	return origin == "http://"+host || (strings.HasPrefix(origin, "http://localhost") && loopbackHost(host))
}

// ApproveResponse is the result of approving a pending lock change.
type ApproveResponse struct {
	Name string         `json:"name"`
	Lock []SectionState `json:"lock"`
}

// handleApprove promotes the pending sections of one server into its lock,
// exactly like `mcp-jail approve <name>`. A running jail picks the new lock
// up on the next list request from the client.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		http.Error(w, "bad server name", http.StatusBadRequest)
		return
	}
	pend, err := lock.LoadPending(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pend == nil || len(pend.Sections) == 0 {
		http.Error(w, "nothing pending for "+name, http.StatusNotFound)
		return
	}
	f, err := lock.Approve(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := ApproveResponse{Name: name, Lock: []SectionState{}}
	for _, k := range lock.Kinds {
		if sec := f.Section(k); sec != nil {
			resp.Lock = append(resp.Lock, SectionState{Kind: string(k), Count: len(sec.Items), Hash: lock.Short(sec.Hash)})
		}
	}
	s.Logf("approved %s from the dashboard: %d section(s)", name, len(pend.Sections))
	writeJSON(w, resp)
}

// handleIndex exchanges ?token= for a cookie, then serves the page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("token"); t != "" {
		if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized: wrong token", http.StatusUnauthorized)
			return
		}
		// Not Secure: the dashboard is plain HTTP on the loopback interface
		// and browsers do not send Secure cookies to http://127.0.0.1.
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}) // #nosec G124
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.authorized(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized: open the URL printed by `mcp-jail ui`", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, static, "static/index.html")
}

// ServerState is one row of the dashboard's server list.
type ServerState struct {
	Name      string         `json:"name"`
	Running   bool           `json:"running"`
	PID       int            `json:"pid,omitempty"`
	StartedAt *time.Time     `json:"started_at,omitempty"`
	LastSeen  *time.Time     `json:"last_seen,omitempty"`
	How       string         `json:"how,omitempty"`
	Network   string         `json:"network,omitempty"`
	Default   string         `json:"tools_default,omitempty"`
	LockOn    bool           `json:"lock_enabled"`
	Lock      []SectionState `json:"lock,omitempty"`
	Pending   *PendingState  `json:"pending,omitempty"`
	Audit     string         `json:"audit,omitempty"`
	Policy    string         `json:"policy,omitempty"`
	Command   []string       `json:"command,omitempty"`
	Counts    map[string]int `json:"counts,omitempty"` // decision -> events in the last 24h
	LastEvent *time.Time     `json:"last_event,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// SectionState summarises one locked list.
type SectionState struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
	Hash  string `json:"hash"`
}

// PendingState is an unapproved change, per section.
type PendingState struct {
	SeenAt   time.Time                 `json:"seen_at"`
	Sections map[string]PendingSection `json:"sections"`
}

// PendingSection lists what changed in one section.
type PendingSection struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

// State is the /api/state document.
type State struct {
	Now      time.Time     `json:"now"`
	Version  string        `json:"version"`
	Servers  []ServerState `json:"servers"`
	Extra    []string      `json:"extra_audit,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

func (s *Server) state() State {
	st := State{Now: s.Now().UTC(), Version: s.version, Extra: s.extra, Servers: []ServerState{}}
	byName := map[string]*ServerState{}
	order := []string{}
	get := func(name string) *ServerState {
		if v, ok := byName[name]; ok {
			return v
		}
		v := &ServerState{Name: name}
		byName[name] = v
		order = append(order, name)
		return v
	}
	known, err := registry.ListKnown()
	if err != nil {
		st.Warnings = append(st.Warnings, err.Error())
	}
	for _, k := range known {
		v := get(k.Name)
		ls := k.LastSeen
		v.LastSeen, v.Audit, v.Policy, v.Command = &ls, k.Audit, k.Policy, k.Command
	}
	live, err := registry.List()
	if err != nil {
		st.Warnings = append(st.Warnings, err.Error())
	}
	for i := range live {
		e := live[i]
		v := get(e.Name)
		sa := e.StartedAt
		v.Running, v.PID, v.StartedAt = true, e.PID, &sa
		v.How, v.Network, v.Default, v.LockOn = e.How, e.Network, e.Default, e.Lock
		v.Audit, v.Policy, v.Command = e.Audit, e.Policy, e.Command
	}
	// locks may exist for servers that never registered (v0.2 runs)
	if ents, err := fs.ReadDir(osDirFS(lock.Dir()), "."); err == nil {
		for _, d := range ents {
			if n, ok := strings.CutSuffix(d.Name(), ".lock.json"); ok {
				get(n)
			}
		}
	}
	for _, name := range order {
		v := byName[name]
		if f, err := lock.Load(name); err != nil {
			v.Error = err.Error()
		} else if f != nil {
			for _, k := range lock.Kinds {
				if sec := f.Section(k); sec != nil {
					v.Lock = append(v.Lock, SectionState{Kind: string(k), Count: len(sec.Items), Hash: lock.Short(sec.Hash)})
				}
			}
			if p, err := lock.LoadPending(name); err != nil {
				v.Error = err.Error()
			} else if p != nil && len(p.Sections) > 0 {
				ps := &PendingState{SeenAt: p.SeenAt, Sections: map[string]PendingSection{}}
				for k, sec := range p.Sections {
					var old map[string]string
					if o := f.Section(k); o != nil {
						old = o.Items
					}
					d := lock.Compare(old, sec.Items)
					ps.Sections[string(k)] = PendingSection{Added: nz(d.Added), Removed: nz(d.Removed), Changed: nz(d.Changed)}
				}
				v.Pending = ps
			}
		}
		if v.Audit != "" {
			since := st.Now.Add(-24 * time.Hour)
			evs, _ := ReadEvents([]string{v.Audit}, Filter{Since: since}, 100000)
			if len(evs) > 0 {
				v.Counts = map[string]int{}
				for _, e := range evs {
					if e.Decision != "" {
						v.Counts[e.Decision]++
					}
				}
				t := evs[0].Time
				v.LastEvent = &t
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := byName[order[i]], byName[order[j]]
		if a.Running != b.Running {
			return a.Running
		}
		return a.Name < b.Name
	})
	for _, n := range order {
		st.Servers = append(st.Servers, *byName[n])
	}
	return st
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// auditPaths lists every audit file the dashboard reads.
func (s *Server) auditPaths() []string { return AuditPaths(s.extra) }

// AuditPaths lists the audit files of every known or running server plus
// extra, absolute, deduplicated and sorted.
func AuditPaths(extra []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if known, err := registry.ListKnown(); err == nil {
		for _, k := range known {
			add(k.Audit)
		}
	}
	if live, err := registry.List(); err == nil {
		for _, e := range live {
			add(e.Audit)
		}
	}
	for _, e := range extra {
		if a, err := filepath.Abs(e); err == nil {
			e = a
		}
		add(e)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.state())
}

// EventsResponse is the /api/events document.
type EventsResponse struct {
	Events  []audit.Event `json:"events"`
	Skipped int           `json:"skipped_lines,omitempty"`
	Files   []string      `json:"files"`
	Limit   int           `json:"limit"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{Server: q.Get("server"), Kind: q.Get("kind"), Decision: q.Get("decision"), Tool: q.Get("tool"), Host: q.Get("host"), Query: q.Get("q")}
	var err error
	if f.Since, err = ParseTime(q.Get("since"), s.Now()); err != nil {
		http.Error(w, "since: "+err.Error(), http.StatusBadRequest)
		return
	}
	if f.Until, err = ParseTime(q.Get("until"), s.Now()); err != nil {
		http.Error(w, "until: "+err.Error(), http.StatusBadRequest)
		return
	}
	limit := 500
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, "limit: positive integer expected", http.StatusBadRequest)
			return
		}
		limit = min(n, 5000)
	}
	files := s.auditPaths()
	if files == nil {
		files = []string{}
	}
	evs, skipped := ReadEvents(files, f, limit)
	if evs == nil {
		evs = []audit.Event{}
	}
	writeJSON(w, EventsResponse{Events: evs, Skipped: skipped, Files: files, Limit: limit})
}

// handleReport aggregates the audit logs over ?since/?until (and ?server);
// ?format=csv returns the per-tool and per-host tables as a download.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{Server: q.Get("server")}
	var err error
	if f.Since, err = ParseTime(q.Get("since"), s.Now()); err != nil {
		http.Error(w, "since: "+err.Error(), http.StatusBadRequest)
		return
	}
	if f.Until, err = ParseTime(q.Get("until"), s.Now()); err != nil {
		http.Error(w, "until: "+err.Error(), http.StatusBadRequest)
		return
	}
	rep := BuildReport(s.auditPaths(), f, s.Now())
	switch q.Get("format") {
	case "", "json":
		writeJSON(w, rep)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="mcp-jail-report.csv"`)
		_ = rep.WriteCSV(w)
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_ = rep.WriteText(w)
	default:
		http.Error(w, "format: json, csv or text", http.StatusBadRequest)
	}
}

// ParseTime accepts RFC 3339, a Go duration meaning "ago" (24h, 15m), or "".
func ParseTime(v string, now time.Time) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("want RFC 3339 or a duration like 24h, got %q", v)
}

// handleStream sends new audit events as server-sent events until the client
// goes away. Each message is `event: audit` with one Event as data; a
// comment line every 15s keeps proxies from closing the connection.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, ": connected\n\n")
	fl.Flush()

	t := NewTailer(s.auditPaths)
	tick := time.NewTicker(s.PollInterval)
	defer tick.Stop()
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-beat.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case <-tick.C:
			evs := t.Poll()
			if len(evs) == 0 {
				continue
			}
			for _, e := range evs {
				b, err := json.Marshal(e)
				if err != nil {
					continue
				}
				_, _ = fmt.Fprintf(w, "event: audit\ndata: %s\n\n", b)
			}
			fl.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// Serve runs the HTTP server on l until ctx is done.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
