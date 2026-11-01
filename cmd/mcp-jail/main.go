// mcp-jail runs any MCP server in a jail: egress allowlist, filesystem
// scope, per-tool policy, rug-pull lock and an audit log.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/netproxy"
	"github.com/ltchurik/mcp-jail/internal/policy"
	"github.com/ltchurik/mcp-jail/internal/proxy"
	"github.com/ltchurik/mcp-jail/internal/sandbox"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `mcp-jail %s — run any MCP server in a jail

Usage:
  mcp-jail run  --policy FILE -- <server command> [args...]
  mcp-jail init [--policy FILE]        write a starter policy
  mcp-jail diff    <name>              show pending tool changes
  mcp-jail approve <name>              accept pending tool changes
  mcp-jail reset   <name>              forget the lock
  mcp-jail locks                       list locks
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
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "reset":
		err = cmdReset(os.Args[2:])
	case "locks":
		err = cmdLocks()
	case "version", "--version", "-v":
		fmt.Println("mcp-jail", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-jail:", err)
		os.Exit(1)
	}
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
	defer al.Close()

	spec := sandbox.Spec{Command: cmdline, Env: map[string]string{}}
	if p.Network.Mode == policy.NetAllowlist {
		np, err := netproxy.Listen(p, func(host string, ok bool) {
			dec := "allow"
			if !ok {
				dec = "blocked"
				logf("net: blocked %s", host)
			}
			al.Log(audit.Event{Kind: "net", Host: host, Decision: dec})
		})
		if err != nil {
			return fmt.Errorf("netproxy: %w", err)
		}
		defer np.Close()
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			spec.Env[k] = np.Addr()
		}
		spec.Env["NO_PROXY"] = ""
		spec.Env["no_proxy"] = ""
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}()

	px := &proxy.Proxy{Policy: p, Audit: al, Logf: logf}
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
		os.Exit(code)
	}
	return nil
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
	if err := os.WriteFile(*out, []byte(policy.Example), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", *out)
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
	if pend == nil {
		fmt.Println("nothing pending for", name)
		return nil
	}
	var old map[string]string
	if cur != nil {
		old = cur.Tools
	}
	d := lock.Compare(old, pend.Tools)
	fmt.Printf("pending change for %s (seen %s)\n", name, pend.SeenAt.Format("2006-01-02 15:04:05 UTC"))
	for _, n := range d.Added {
		fmt.Println("  + added  ", n)
	}
	for _, n := range d.Removed {
		fmt.Println("  - removed", n)
	}
	for _, n := range d.Changed {
		fmt.Println("  ~ changed", n)
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
	fmt.Printf("approved %s: %d tools, %s\n", name, len(f.Tools), f.Hash[:12])
	return nil
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
		if pend != nil {
			flag = "  [PENDING CHANGE]"
		}
		fmt.Printf("%-24s %3d tools  %s  %s%s\n", f.Name, len(f.Tools), f.Hash[:12], f.UpdatedAt.Format("2006-01-02"), flag)
	}
	return nil
}
