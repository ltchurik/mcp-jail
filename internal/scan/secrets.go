package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// secretPattern recognises one kind of credential by shape.
type secretPattern struct {
	rule string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"aws-access-key", regexp.MustCompile(`\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	{"private-key", regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"github-token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"openai-key", regexp.MustCompile(`\bsk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b`)},
	{"anthropic-key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"stripe-key", regexp.MustCompile(`\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b`)},
	{"sendgrid-key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`)},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"pypi-token", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b`)},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}`)},
	{"basic-auth-url", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{4,}@`)},
	{"password-assignment", regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']?[^\s"',;]{8,}`)},
}

// SecretRules lists every secrets rule id.
var SecretRules = func() []string {
	out := make([]string, 0, len(secretPatterns)+1)
	for _, p := range secretPatterns {
		out = append(out, p.rule)
	}
	return append(out, "env-value")
}()

// SecretOptions tune Secrets.
type SecretOptions struct {
	// Env maps the names of secret-looking host environment variables to
	// their values (see EnvSecrets): an argument carrying one of these
	// values is a credential leaving the machine, whatever it looks like.
	Env map[string]string
	// Ignore lists rule ids that are not reported.
	Ignore []string
}

// envSecretName is a variable name that usually holds a credential.
var envSecretName = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|api[_-]?key|private[_-]?key|credential|_auth$|^auth_|access[_-]?key|session[_-]?key)`)

// EnvSecrets picks the credentials out of an environment (os.Environ()
// shape): variables with a telling name and a value long enough to be
// one. Values shorter than 12 bytes would match everywhere.
func EnvSecrets(environ []string) map[string]string {
	out := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && len(v) >= 12 && envSecretName.MatchString(k) {
			out[k] = v
		}
	}
	return out
}

// Secrets scans every string of a tools/call arguments object for things
// that look like credentials. The findings name the rule and where, never
// the value: a detail is the rule's shape or the environment variable's
// name plus the length of what matched.
func Secrets(args json.RawMessage, o SecretOptions) []Finding {
	if len(args) == 0 || string(args) == "null" {
		return nil
	}
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		return nil // the proxy refused unparsable arguments already
	}
	ignored := func(rule string) bool {
		for _, i := range o.Ignore {
			if i == rule {
				return true
			}
		}
		return false
	}
	envNames := make([]string, 0, len(o.Env))
	for k := range o.Env {
		envNames = append(envNames, k)
	}
	sort.Strings(envNames)
	var out []Finding
	walk(v, "", func(where, s string) {
		seen := map[string]bool{}
		for _, p := range secretPatterns {
			if seen[p.rule] || ignored(p.rule) {
				continue
			}
			if m := p.re.FindString(s); m != "" {
				seen[p.rule] = true
				out = append(out, Finding{Rule: p.rule, Where: where, Detail: fmt.Sprintf("%d bytes", len(m))})
			}
		}
		if ignored("env-value") {
			return
		}
		for _, k := range envNames {
			if strings.Contains(s, o.Env[k]) {
				out = append(out, Finding{Rule: "env-value", Where: where, Detail: "value of $" + k})
			}
		}
	})
	return out
}
