package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Lint reports rules that are wider than the mounts they sit on: an
// args.under directory that no read_write path covers, so a write there
// passes the policy and then fails inside the jail as a read-only
// filesystem error instead of "denied by policy"; and one that no mount
// covers at all, so every call there fails inside the jail. The policy
// cannot tell which tools write, so these are warnings, not errors: a
// read-only tool legitimately points under: at a read_only path.
//
// Nothing is reported for a remote server or a disabled sandbox, where
// the filesystem section does not apply.
func (p *Policy) Lint() []string {
	if p.Remote() || p.Sandbox.Disabled {
		return nil
	}
	names := make([]string, 0, len(p.Tools.Rules))
	for n := range p.Tools.Rules {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		r := p.Tools.Rules[n]
		if r.Decision == Deny {
			continue
		}
		args := make([]string, 0, len(r.Args))
		for a := range r.Args {
			args = append(args, a)
		}
		sort.Strings(args)
		for _, a := range args {
			for _, d := range r.Args[a].Under {
				where := fmt.Sprintf("tools.rules[%s].args.%s: %s", n, a, d)
				switch {
				case covered(d, p.Filesystem.ReadWrite):
				case covered(d, p.Filesystem.ReadOnly):
					out = append(out, where+" is read-only inside the jail (not inside read_write): a write there fails as a filesystem error, not as denied by policy")
				default:
					out = append(out, where+" is not shared into the jail (not inside read_only or read_write): calls there pass the policy and fail inside the jail")
				}
			}
		}
	}
	return out
}

// covered reports whether path is one of dirs or inside one of them.
func covered(path string, dirs []string) bool {
	path = filepath.Clean(path)
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}
