// Package launcher looks at a server command line and says when the
// program that will run is decided at start time rather than by the policy:
// an npx or uvx package without an exact version, a docker image without a
// digest, a remote module, a script piped from the network. The lock pins
// what the server says; exec.sha256 pins a file; neither helps when the
// registry decides which code runs today.
package launcher

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Check returns one warning per unpinned program in cmdline; nil when the
// command line names what runs.
func Check(cmdline []string) []string {
	if len(cmdline) == 0 {
		return nil
	}
	cmd := filepath.Base(cmdline[0])
	args := cmdline[1:]
	switch cmd {
	case "npx", "bunx":
		return npmSpecs(cmd, args)
	case "npm":
		if len(args) > 0 && (args[0] == "exec" || args[0] == "x") {
			return npmSpecs("npm exec", args[1:])
		}
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			return npmSpecs(cmd+" dlx", args[1:])
		}
	case "uvx":
		return pySpecs("uvx", args, "--from")
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			return pySpecs("uv tool run", args[2:], "--from")
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			return pySpecs("pipx run", args[1:], "--spec")
		}
	case "deno":
		return denoSpecs(args)
	case "docker", "podman", "nerdctl":
		if len(args) > 0 && args[0] == "run" {
			return dockerImage(cmd, args[1:])
		}
	case "sh", "bash", "zsh", "dash":
		return shellScript(cmd, args)
	}
	return nil
}

// exact semver, optionally with pre-release and build metadata
var semver = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// npmFlagsWithValue take the next argument.
var npmFlagsWithValue = map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true, "--loglevel": true, "--registry": true, "--shell": true, "--workspace": true, "-w": true, "--prefix": true}

// npmSpecs reports the npm packages the launcher resolves at run time: the
// -p/--package specs when given, otherwise the first positional argument.
func npmSpecs(tool string, args []string) []string {
	var specs []string
	var positional string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if positional == "" && i+1 < len(args) {
				positional = args[i+1]
			}
			i = len(args)
		case strings.HasPrefix(a, "--package=") || strings.HasPrefix(a, "-p="):
			specs = append(specs, a[strings.Index(a, "=")+1:])
		case a == "-p" || a == "--package":
			if i+1 < len(args) {
				specs = append(specs, args[i+1])
				i++
			}
		case npmFlagsWithValue[a]:
			i++
		case strings.HasPrefix(a, "-"):
		case positional == "":
			positional = a
		}
	}
	if len(specs) == 0 && positional != "" {
		specs = []string{positional}
	}
	var out []string
	for _, s := range specs {
		if isLocal(s) {
			continue
		}
		name, ver := splitNpm(s)
		if ver != "" && semver.MatchString(ver) {
			continue
		}
		out = append(out, unpinned(tool, s, name+"@"+exampleNpm(ver)))
	}
	return out
}

// splitNpm separates "@scope/name@spec" into name and spec.
func splitNpm(s string) (string, string) {
	i := strings.LastIndex(s, "@")
	if i <= 0 { // no version, or a scoped name without one
		return s, ""
	}
	return s[:i], s[i+1:]
}

func exampleNpm(spec string) string {
	switch spec {
	case "", "latest", "next":
		return "1.2.3"
	}
	// a range: show its first concrete number
	n := regexp.MustCompile(`\d+(\.\d+)*`).FindString(spec)
	switch strings.Count(n, ".") {
	case 0:
		if n == "" {
			return "1.2.3"
		}
		return n + ".0.0"
	case 1:
		return n + ".0"
	}
	return n
}

// pySpecs reports the Python packages uvx / pipx resolve at run time: the
// --from (--spec) value when given, otherwise the first positional.
func pySpecs(tool string, args []string, fromFlag string) []string {
	var spec, positional string
	valued := map[string]bool{fromFlag: true, "--with": true, "--python": true, "-p": true, "--index": true, "--index-url": true, "--extra-index-url": true, "--index-strategy": true, "--cache-dir": true, "--directory": true, "--project": true, "--with-requirements": true, "--with-editable": true, "--constraints": true, "--find-links": true, "-f": true, "--pip-args": true, "--python-preference": true, "--color": true, "--config-file": true, "--resolution": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if positional == "" && i+1 < len(args) {
				positional = args[i+1]
			}
			i = len(args)
		case strings.HasPrefix(a, fromFlag+"="):
			spec = a[len(fromFlag)+1:]
		case a == fromFlag:
			if i+1 < len(args) {
				spec = args[i+1]
				i++
			}
		case valued[a]:
			i++
		case strings.HasPrefix(a, "-"):
		case positional == "":
			positional = a
		}
	}
	if spec == "" {
		spec = positional
	}
	if spec == "" || isLocal(spec) {
		return nil
	}
	if pinnedPy(spec) {
		return nil
	}
	name := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`).FindString(spec)
	if name == "" {
		name = spec
	}
	return []string{unpinned(tool, spec, name+"==1.2.3")}
}

// pinnedPy accepts "pkg==1.2.3" (extras allowed), "pkg@1.2.3" and a git URL
// pinned to a full commit.
func pinnedPy(spec string) bool {
	if i := strings.Index(spec, "git+"); i >= 0 {
		return regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(spec)
	}
	if i := strings.Index(spec, "=="); i >= 0 {
		return semver.MatchString(strings.TrimSpace(spec[i+2:])) || regexp.MustCompile(`^\d+(\.\d+)+([a-z]+\d*)?$`).MatchString(strings.TrimSpace(spec[i+2:]))
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return semver.MatchString(spec[i+1:])
	}
	return false
}

// denoSpecs flags a remote module or an unversioned registry specifier.
func denoSpecs(args []string) []string {
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "https://") || strings.HasPrefix(a, "http://"):
			return []string{"deno runs a remote module (" + a + ") fetched at start: whoever controls that URL controls the server; vendor it or pin it with a lock file"}
		case strings.HasPrefix(a, "npm:") || strings.HasPrefix(a, "jsr:"):
			name, ver := splitNpm(strings.TrimPrefix(strings.TrimPrefix(a, "npm:"), "jsr:"))
			if ver != "" && semver.MatchString(ver) {
				return nil
			}
			return []string{unpinned("deno", a, a[:4]+name+"@"+exampleNpm(ver))}
		}
	}
	return nil
}

// dockerFlagsWithValue take the next argument.
var dockerFlagsWithValue = map[string]bool{"-v": true, "--volume": true, "-e": true, "--env": true, "-p": true, "--publish": true, "--name": true, "--network": true, "--net": true, "-w": true, "--workdir": true, "-u": true, "--user": true, "--entrypoint": true, "--mount": true, "-l": true, "--label": true, "--env-file": true, "--platform": true, "--pull": true, "--restart": true, "-m": true, "--memory": true, "--cpus": true, "--add-host": true, "--device": true, "--cap-add": true, "--cap-drop": true, "--security-opt": true, "--tmpfs": true, "-h": true, "--hostname": true, "--log-driver": true, "--log-opt": true, "--shm-size": true, "--ulimit": true, "--group-add": true, "--dns": true, "--pid": true, "--ipc": true, "--uts": true, "--userns": true, "--cgroupns": true, "--runtime": true, "--stop-signal": true, "--stop-timeout": true, "--health-cmd": true, "--expose": true, "--link": true, "--volumes-from": true, "--sysctl": true, "--storage-opt": true, "--cidfile": true, "--gpus": true, "--isolation": true, "--mac-address": true, "--ip": true, "--ip6": true, "--memory-swap": true, "--cpu-shares": true, "--cpuset-cpus": true, "--blkio-weight": true, "--oom-score-adj": true, "--pids-limit": true, "--annotation": true}

// dockerImage flags an image that is not pinned to a digest.
func dockerImage(tool string, args []string) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case dockerFlagsWithValue[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if strings.Contains(a, "@sha256:") {
				return nil
			}
			ex := a
			if j := strings.LastIndex(ex, ":"); j > strings.LastIndex(ex, "/") {
				ex = ex[:j]
			}
			return []string{tool + " run resolves the image " + q(a) + " at every start: a tag can move; pin the digest, e.g. " + q(ex+"@sha256:<digest>")}
		}
	}
	return nil
}

var pipeToShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)

// shellScript flags "sh -c" scripts that fetch and run code.
func shellScript(tool string, args []string) []string {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			if pipeToShell.MatchString(args[i+1]) {
				return []string{tool + " -c fetches a script from the network and runs it at every start: install it once and point the command at the file"}
			}
			return nil
		}
	}
	return nil
}

func isLocal(spec string) bool {
	return strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~") || strings.HasPrefix(spec, "file:")
}

func unpinned(tool, spec, example string) string {
	return tool + " resolves " + q(spec) + " at every start: the registry's current version runs, not one you reviewed; pin it, e.g. " + q(example) + ", or install it once and set exec.allow / exec.sha256"
}

// q quotes a value for a message.
func q(s string) string { return `"` + s + `"` }
