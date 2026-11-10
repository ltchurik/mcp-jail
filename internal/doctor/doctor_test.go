package doctor

import (
	"errors"
	"strings"
	"testing"
)

func fake(goos string, have map[string]string, outputs map[string]string, files map[string]string) Host {
	return Host{
		GOOS: goos, GOARCH: "amd64", StateDir: "",
		Look: func(name string) (string, error) {
			if p, ok := have[name]; ok {
				return p, nil
			}
			return "", errors.New("not found")
		},
		Run: func(name string, args ...string) (string, error) {
			key := name + " " + strings.Join(args, " ")
			for k, v := range outputs {
				if strings.HasPrefix(key, k) {
					if strings.HasPrefix(v, "ERR ") {
						return strings.TrimPrefix(v, "ERR "), errors.New("exit 1")
					}
					return v, nil
				}
			}
			return "", errors.New("exit 1")
		},
		Read: func(path string) (string, error) {
			if v, ok := files[path]; ok {
				return v, nil
			}
			return "", errors.New("no such file")
		},
	}
}

func status(r Report, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "absent"
}

func TestLinuxAllGood(t *testing.T) {
	h := fake("linux", map[string]string{"bwrap": "/usr/bin/bwrap", "docker": "/usr/bin/docker"},
		map[string]string{"/usr/bin/bwrap --version": "bubblewrap 0.9.0", "/usr/bin/bwrap --unshare-user-try": "", "/usr/bin/docker info": "28.1.0"},
		map[string]string{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "0"})
	r := Run(h, "test")
	if !r.Usable || r.Native != "bwrap" || !r.Docker || status(r, "bwrap probe") != OK || status(r, "user namespaces") != "absent" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Summary, "both usable") {
		t.Fatalf("summary: %s", r.Summary)
	}
}

func TestLinuxApparmorAndOldBwrap(t *testing.T) {
	h := fake("linux", map[string]string{"bwrap": "/usr/bin/bwrap"},
		map[string]string{"/usr/bin/bwrap --version": "bubblewrap 0.4.1", "/usr/bin/bwrap --unshare-user-try": ""},
		map[string]string{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1"})
	r := Run(h, "test")
	if status(r, "bwrap") != Warn || status(r, "user namespaces") != Warn || r.Native != "bwrap" || r.Docker {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Summary, "no docker or podman") {
		t.Fatalf("summary: %s", r.Summary)
	}
}

func TestLinuxNothingUsable(t *testing.T) {
	h := fake("linux", map[string]string{"bwrap": "/usr/bin/bwrap", "docker": "/usr/bin/docker"},
		map[string]string{"/usr/bin/bwrap --version": "bubblewrap 0.9.0", "/usr/bin/bwrap --unshare-user-try": "ERR bwrap: No permissions to create a new namespace", "/usr/bin/docker info": "ERR Cannot connect to the Docker daemon"},
		map[string]string{"/proc/sys/user/max_user_namespaces": "0"})
	r := Run(h, "test")
	if r.Usable || r.Native != "" || r.Docker || status(r, "user namespaces") != Missing || status(r, "bwrap probe") != Missing || status(r, "docker") != Warn {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Summary, "no sandbox can be set up") {
		t.Fatalf("summary: %s", r.Summary)
	}
}

func TestDarwinAndWindows(t *testing.T) {
	r := Run(fake("darwin", map[string]string{"sandbox-exec": "/usr/bin/sandbox-exec", "docker": "/usr/local/bin/docker"}, map[string]string{"/usr/local/bin/docker info": "28.0.1"}, nil), "test")
	if !r.Usable || r.Native != "sandbox-exec" || !r.Docker {
		t.Fatalf("darwin: %+v", r)
	}
	for _, c := range r.Checks {
		if c.Name == "docker" && !strings.Contains(c.Detail, "needs a Linux host") {
			t.Fatalf("docker on darwin must mention the allowlist limit: %+v", c)
		}
	}
	r = Run(fake("windows", map[string]string{"docker": `C:\docker.exe`}, map[string]string{`C:\docker.exe info`: "28.0.1"}, nil), "test")
	if !r.Usable || r.Native != "" || !r.Docker || !strings.Contains(r.Summary, "use sandbox.backend: docker") {
		t.Fatalf("windows: %+v", r)
	}
	r = Run(fake("windows", nil, nil, nil), "test")
	if r.Usable || status(r, "native sandbox") != Missing || status(r, "docker") != Missing {
		t.Fatalf("bare windows: %+v", r)
	}
}
