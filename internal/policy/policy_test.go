package policy

import "testing"

func TestDecide(t *testing.T) {
	p := Default()
	p.Tools.Default = Ask
	p.Tools.Rules = map[string]Decision{
		"read_*":    Allow,
		"read_file": Deny,
		"*":         Deny,
		"list_*":    Allow,
	}
	cases := map[string]Decision{
		"read_file":  Deny,  // exact beats glob
		"read_dir":   Allow, // longest glob beats "*"
		"list_tools": Allow,
		"write_file": Deny, // "*"
	}
	for tool, want := range cases {
		if got := p.Decide(tool); got != want {
			t.Errorf("Decide(%q) = %s, want %s", tool, got, want)
		}
	}
	p.Tools.Rules = nil
	if got := p.Decide("anything"); got != Ask {
		t.Errorf("default: got %s", got)
	}
}

func TestHostAllowed(t *testing.T) {
	p := Default()
	p.Network.Allow = []string{"api.github.com", "*.githubusercontent.com"}
	for host, want := range map[string]bool{
		"api.github.com":              true,
		"API.GITHUB.COM.":             true,
		"raw.githubusercontent.com":   true,
		"githubusercontent.com":       false,
		"evil-api.github.com":         false,
		"api.github.com.evil.example": false,
	} {
		if got := p.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	p := Default()
	p.Network.Mode = "sometimes"
	if err := p.Validate(); err == nil {
		t.Error("expected error for bad network.mode")
	}
	p = Default()
	p.Network.Mode = NetAllowlist
	if err := p.Validate(); err == nil {
		t.Error("expected error for allowlist without hosts")
	}
	p = Default()
	p.Tools.Rules = map[string]Decision{"x": "maybe"}
	if err := p.Validate(); err == nil {
		t.Error("expected error for bad decision")
	}
}
