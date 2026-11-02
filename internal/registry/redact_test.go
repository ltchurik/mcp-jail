package registry

import (
	"reflect"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]struct{ in, want []string }{
		"flag then value":   {[]string{"srv", "--token", "abc", "--port", "80"}, []string{"srv", "--token", "***", "--port", "80"}},
		"flag=value":        {[]string{"srv", "--api-key=abc", "-p", "x"}, []string{"srv", "--api-key=***", "-p", "x"}},
		"env pair":          {[]string{"env", "GITHUB_TOKEN=ghp_x", "npx", "srv"}, []string{"env", "GITHUB_TOKEN=***", "npx", "srv"}},
		"url password":      {[]string{"srv", "postgres://bob:pw@db/x"}, []string{"srv", "postgres://bob:***@db/x"}},
		"url without pw":    {[]string{"srv", "https://bob@host/x"}, []string{"srv", "https://bob@host/x"}},
		"known prefix":      {[]string{"srv", "ghp_abcdefghijklmnop", "sk-abcdefghijkl"}, []string{"srv", "***", "***"}},
		"plain args":        {[]string{"npx", "-y", "@scope/server", "/srv/proj", "--keyboard"}, []string{"npx", "-y", "@scope/server", "/srv/proj", "--keyboard"}},
		"argv0 never":       {[]string{"token", "x"}, []string{"token", "x"}},
		"keyfile is a path": {[]string{"srv", "--key-file", "/etc/x"}, []string{"srv", "--key-file", "/etc/x"}},
		"empty":             {nil, nil},
	}
	for name, c := range cases {
		if got := Redact(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Redact(%q) = %q, want %q", name, c.in, got, c.want)
		}
	}
	in := []string{"srv", "--token", "abc"}
	_ = Redact(in)
	if in[2] != "abc" {
		t.Error("Redact must not modify its input")
	}
}
