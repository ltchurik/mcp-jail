// mcp-jail runs any MCP server in a jail: egress allowlist, filesystem
// scope, per-tool policy, rug-pull lock and an audit log.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/control"
	"github.com/ltchurik/mcp-jail/internal/egress"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/netproxy"
	"github.com/ltchurik/mcp-jail/internal/policy"
	"github.com/ltchurik/mcp-jail/internal/proxy"
	"github.com/ltchurik/mcp-jail/internal/registry"
	"github.com/ltchurik/mcp-jail/internal/sandbox"
	"github.com/ltchurik/mcp-jail/internal/ui"
	"github.com/ltchurik/mcp-jail/internal/wrap"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `mcp-jail %s — run any MCP server in a jail

Usage:
  mcp-jail run  --policy FILE -- <server command> [args...]
  mcp-jail init [--policy FILE]        write a starter policy
  mcp-jail wrap <client-config.json>   route every server in a client config through mcp-jail
  mcp-jail diff    <name>              show pending tool changes
  mcp-jail approve <name>              accept pending tool changes
  mcp-jail reset   <name>              forget the lock
  mcp-jail locks                       list locks
  mcp-jail ps                          list running jails
  mcp-jail ui   [--listen 127.0.0.1:0] [--audit FILE]...
                                       local dashboard: servers, audit events, pending changes
  mcp-jail report [--since 24h] [--server NAME] [--json|--csv] [--audit FILE]...
                                       summarise the audit logs
  mcp-jail version

Client config (Claude Desktop, Cursor, Claude Code, …):
  "command": "mcp-jail",
  "args": ["run", "--policy", "/path/policy.yml", "--", "npx", "-y", "@scope/server"]
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "wrap":
		err = cmdWrap(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "reset":
		err = cmdReset(os.Args[2:])
	case "locks":
		err = cmdLocks()
	case "ps":
		err = cmdPS()
	case "ui":
		err = cmdUI(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case sandbox.ShimCommand: // internal: mcp-jail re-executed inside the jail
		code, err := cmdShim(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "mcp-jail:", err)
		}
		os.Exit(code)
	case "version", "--version", "-v":
		fmt.Println("mcp-jail", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	var ec exitCode
	if errors.As(err, &ec) {
		os.Exit(int(ec))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-jail:", err)
		os.Exit(1)
	}
}

// exitCode propagates the jailed server's exit status after deferred
// cleanup (audit close, registry entry) has run.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("server exited with %d", int(e)) }

// absPath is best effort: a relative path stays relative if Abs fails.
func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[mcp-jail] "+format+"\n", args...)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	pol := fs.String("policy", "", "policy file (yaml)")
	quiet := fs.Bool("quiet", false, "no startup banner on stderr")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdline := fs.Args()
	if *pol == "" {
		return errors.New("--policy is required")
	}
	if len(cmdline) == 0 {
		return errors.New("server command missing after --")
	}

	p, err := policy.Load(*pol)
	if err != nil {
		return err
	}
	if p.Name == "" {
		p.Name = filepath.Base(cmdline[0])
	}

	al, err := audit.Open(p.Audit.Path, p.Name)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = al.Close() }()

	work, err := os.MkdirTemp("", "mcp-jail-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	spec := sandbox.Spec{Command: cmdline, Env: map[string]string{}, WorkDir: work}
	netObserve := func(kind, host string, ok bool) {
		dec := "allow"
		if !ok {
			dec = "blocked"
			logf("%s: blocked %s", kind, host)
		}
		al.Log(audit.Event{Kind: kind, Host: host, Decision: dec})
	}
	switch {
	case sandbox.HardEgress(p):
		// Linux: the jail has no network; the shim inside it reaches the host
		// only through this relay, which enforces network.allow.
		relay, err := egress.ListenRelay(p, netObserve)
		if err != nil {
			return fmt.Errorf("egress relay: %w", err)
		}
		defer func() { _ = relay.Close() }()
		resolv := filepath.Join(relay.Dir(), "resolv.conf")
		if err := os.WriteFile(resolv, []byte(egress.ResolvConf), 0o600); err != nil {
			return fmt.Errorf("egress relay: %w", err)
		}
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("egress relay: locate mcp-jail binary: %w", err)
		}
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		spec.Egress = &sandbox.Egress{Dir: relay.Dir(), Exe: exe, Allow: p.Network.Allow,
			UID: os.Getuid(), GID: os.Getgid(), ResolvConf: resolv}
		for k, v := range egress.ProxyEnv() {
			spec.Env[k] = v
		}
	case p.Network.Mode == policy.NetAllowlist:
		// HTTP_PROXY filtering. Cooperative without a sandbox; on macOS the
		// sandbox-exec profile lets the server reach only this port.
		np, err := netproxy.Listen(p, func(host string, ok bool) { netObserve("net", host, ok) })
		if err != nil {
			return fmt.Errorf("netproxy: %w", err)
		}
		defer func() { _ = np.Close() }()
		spec.ProxyPort = np.Port()
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			spec.Env[k] = np.Addr()
		}
		spec.Env["NO_PROXY"] = ""
		spec.Env["no_proxy"] = ""
		spec.Env["NODE_USE_ENV_PROXY"] = "1"
	}

	cmd, how, err := sandbox.Build(p, spec)
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	sin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	sout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	if !*quiet {
		logf("%s: %s | net=%s tools.default=%s lock=%v", p.Name, how, p.Network.Mode, p.Tools.Default, p.Lock.Enabled)
	}
	al.Log(audit.Event{Kind: "start", Reason: how})
	// control socket: the dashboard answers `ask` decisions through it
	asks := control.NewBroker(p.Name)
	controlPath := ""
	if cs, err := control.Listen(control.SocketPath(registry.Dir(), p.Name, os.Getpid()), asks); err != nil {
		logf("control socket: %v (the dashboard cannot answer asks for this jail)", err)
		asks = nil
	} else {
		controlPath = cs.Path()
		defer func() { _ = cs.Close() }()
	}
	if unregister, err := registry.Register(registry.Entry{
		Name: p.Name, Policy: absPath(*pol), Audit: p.Audit.Path, Command: cmdline, How: how,
		Network: string(p.Network.Mode), Default: string(p.Tools.Default), Lock: p.Lock.Enabled,
		Control: controlPath,
	}); err != nil {
		logf("registry: %v (dashboard will not list this jail)", err)
	} else {
		defer unregister()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}()

	px := &proxy.Proxy{Policy: p, Audit: al, Logf: logf, Asks: asks}
	runErr := px.Run(os.Stdin, os.Stdout, sin, sout)
	_ = sin.Close()
	waitErr := cmd.Wait()

	code := 0
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		code = ee.ExitCode()
	}
	al.Log(audit.Event{Kind: "exit", Reason: fmt.Sprint(code)})
	if runErr != nil && !errors.Is(runErr, os.ErrClosed) {
		return runErr
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// cmdShim runs inside the jail: see package egress.
func cmdShim(args []string) (int, error) {
	fs := flag.NewFlagSet(sandbox.ShimCommand, flag.ContinueOnError)
	sock := fs.String("socket", "", "relay socket")
	allow := fs.String("allow", "", "comma-separated network.allow")
	uid := fs.Int("uid", os.Getuid(), "uid for the server")
	gid := fs.Int("gid", os.Getgid(), "gid for the server")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *sock == "" {
		return 2, errors.New("egress shim: --socket is required")
	}
	var hosts []string
	for _, h := range strings.Split(*allow, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return egress.RunShim(*sock, hosts, *uid, *gid, fs.Args(), logf)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	out := fs.String("policy", "policy.yml", "where to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists", *out)
	}
	if err := os.WriteFile(*out, []byte(policy.Example), 0o600); err != nil {
		return err
	}
	fmt.Println("wrote", *out)
	return nil
}

// cmdWrap rewrites a client configuration so each stdio server starts
// through mcp-jail and writes one starter policy per server.
func cmdWrap(args []string) error {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	polDir := fs.String("policy-dir", filepath.Join(filepath.Dir(lock.Dir()), "policies"), "where to write <server>.yml policies")
	bin := fs.String("bin", "", "mcp-jail binary to reference (default: this executable's absolute path)")
	network := fs.String("network", "none", "network.mode for new policies: none | all")
	force := fs.Bool("force", false, "overwrite existing policy files")
	dry := fs.Bool("dry-run", false, "print the rewritten config, write nothing")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("expected exactly one client config file (Claude Desktop, Cursor, .mcp.json, ...)")
	}
	if *bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		*bin = exe
	}
	res, err := wrap.Run(fs.Arg(0), wrap.Options{Bin: *bin, PolicyDir: *polDir, Network: *network, Force: *force, DryRun: *dry})
	if err != nil {
		return err
	}
	if *dry {
		_, _ = os.Stdout.Write(res.Config)
	}
	wrapped := 0
	for _, c := range res.Changes {
		switch c.Action {
		case "wrapped":
			wrapped++
			note := ""
			if c.Note != "" {
				note = " (" + c.Note + ")"
			}
			fmt.Fprintf(os.Stderr, "  wrapped  %-24s policy %s%s\n", c.Name, c.Policy, note)
		case "already-wrapped":
			fmt.Fprintf(os.Stderr, "  skipped  %-24s already runs through mcp-jail\n", c.Name)
		default:
			fmt.Fprintf(os.Stderr, "  skipped  %-24s %s\n", c.Name, c.Note)
		}
	}
	switch {
	case *dry:
		fmt.Fprintf(os.Stderr, "dry run: %d server(s) would be wrapped; nothing written\n", wrapped)
	case res.Backup != "":
		fmt.Fprintf(os.Stderr, "wrote %s (backup: %s)\n", fs.Arg(0), res.Backup)
		fmt.Fprintf(os.Stderr, "review the policies in %s, then restart the client\n", *polDir)
	default:
		fmt.Fprintln(os.Stderr, "nothing to do")
	}
	return nil
}

func nameArg(args []string) (string, error) {
	if len(args) != 1 || args[0] == "" {
		return "", errors.New("expected <name> (the policy's name:)")
	}
	return args[0], nil
}

func cmdDiff(args []string) error {
	name, err := nameArg(args)
	if err != nil {
		return err
	}
	cur, err := lock.Load(name)
	if err != nil {
		return err
	}
	pend, err := lock.LoadPending(name)
	if err != nil {
		return err
	}
	if pend == nil || len(pend.Sections) == 0 {
		fmt.Println("nothing pending for", name)
		return nil
	}
	fmt.Printf("pending change for %s (seen %s)\n", name, pend.SeenAt.Format("2006-01-02 15:04:05 UTC"))
	for _, k := range lock.Kinds {
		sec, ok := pend.Sections[k]
		if !ok {
			continue
		}
		var old map[string]string
		if o := cur.Section(k); o != nil {
			old = o.Items
		}
		d := lock.Compare(old, sec.Items)
		fmt.Printf("%s:\n", k)
		for _, n := range d.Added {
			fmt.Println("  + added  ", n)
		}
		for _, n := range d.Removed {
			fmt.Println("  - removed", n)
		}
		for _, n := range d.Changed {
			fmt.Println("  ~ changed", n)
		}
	}
	fmt.Println("\nreview the server, then: mcp-jail approve", name)
	return nil
}

func cmdApprove(args []string) error {
	name, err := nameArg(args)
	if err != nil {
		return err
	}
	f, err := lock.Approve(name)
	if err != nil {
		return err
	}
	fmt.Printf("approved %s: %s\n", name, summarize(f))
	return nil
}

// summarize renders "11 tools 5dc4bc0b04d6, 2 prompts 1a2b..." for a lock.
func summarize(f *lock.File) string {
	var parts []string
	for _, k := range lock.Kinds {
		if sec := f.Section(k); sec != nil {
			parts = append(parts, fmt.Sprintf("%d %s %s", len(sec.Items), strings.ReplaceAll(string(k), "_", " "), lock.Short(sec.Hash)))
		}
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, ", ")
}

func cmdReset(args []string) error {
	name, err := nameArg(args)
	if err != nil {
		return err
	}
	if err := lock.Reset(name); err != nil {
		return err
	}
	fmt.Println("lock removed for", name)
	return nil
}

func cmdLocks() error {
	ents, err := os.ReadDir(lock.Dir())
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no locks in", lock.Dir())
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".lock.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(lock.Dir(), e.Name()))
		if err != nil {
			continue
		}
		var f lock.File
		if json.Unmarshal(b, &f) != nil {
			continue
		}
		pend, _ := lock.LoadPending(f.Name)
		flag := ""
		if pend != nil && len(pend.Sections) > 0 {
			flag = "  [PENDING CHANGE]"
		}
		fmt.Printf("%-24s %s  %s%s\n", f.Name, f.UpdatedAt.Format("2006-01-02"), summarize(&f), flag)
	}
	return nil
}

func cmdPS() error {
	if _, err := registry.Prune(); err != nil {
		return err
	}
	live, err := registry.List()
	if err != nil {
		return err
	}
	if len(live) == 0 {
		fmt.Println("no running jails")
		return nil
	}
	now := time.Now()
	for _, e := range live {
		up := now.Sub(e.StartedAt).Round(time.Second)
		fmt.Printf("%-20s pid %-7d up %-10s %-12s net=%-9s tools.default=%-5s %s\n",
			e.Name, e.PID, up, e.How, e.Network, e.Default, strings.Join(e.Command, " "))
	}
	return nil
}

func cmdUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:0", "address to bind; must be loopback")
	var extra stringList
	fs.Var(&extra, "audit", "additional audit log to show (repeatable)")
	openBrowser := fs.Bool("open", false, "open the dashboard in the default browser")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("ui takes no positional arguments")
	}
	token, err := ui.NewToken()
	if err != nil {
		return err
	}
	srv, err := ui.New(token, version, extra)
	if err != nil {
		return err
	}
	srv.Logf = logf
	l, err := ui.Listen(*listen)
	if err != nil {
		return err
	}
	if _, err := registry.Prune(); err != nil {
		logf("registry: %v", err)
	}
	url := srv.URL(l)
	fmt.Println(url)
	logf("dashboard listening on %s; the token in the URL is the only credential, press Ctrl-C to stop", l.Addr())
	if *openBrowser {
		if err := browse(url); err != nil {
			logf("open browser: %v", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx, l)
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	since := fs.String("since", "24h", "start of the range: a duration ago (24h, 7d is 168h) or RFC 3339")
	until := fs.String("until", "", "end of the range (default now)")
	server := fs.String("server", "", "only this server")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	asCSV := fs.Bool("csv", false, "print the per-tool and per-host tables as CSV")
	var extra stringList
	fs.Var(&extra, "audit", "additional audit log to include (repeatable)")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("report takes no positional arguments")
	}
	if *asJSON && *asCSV {
		return errors.New("--json and --csv are exclusive")
	}
	now := time.Now()
	f := ui.Filter{Server: *server}
	var err error
	if f.Since, err = ui.ParseTime(*since, now); err != nil {
		return fmt.Errorf("--since: %w", err)
	}
	if f.Until, err = ui.ParseTime(*until, now); err != nil {
		return fmt.Errorf("--until: %w", err)
	}
	if _, err := registry.Prune(); err != nil {
		logf("registry: %v", err)
	}
	rep := ui.BuildReport(ui.AuditPaths(extra), f, now)
	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case *asCSV:
		return rep.WriteCSV(os.Stdout)
	default:
		return rep.WriteText(os.Stdout)
	}
}

// browse opens url with the platform's default handler; best effort.
func browse(url string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	return c.Start()
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
