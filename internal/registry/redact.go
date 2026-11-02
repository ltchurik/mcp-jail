package registry

import (
	"net/url"
	"regexp"
	"strings"
)

// Redact returns a copy of argv with values that look like credentials
// replaced by "***": the value after a flag such as --token or --api-key,
// the value part of KEY=VALUE or --flag=value pairs whose key names a
// secret, the password in a URL's userinfo, and tokens with a well-known
// prefix. The registry, `mcp-jail ps` and the dashboard show this copy;
// the jail itself runs the original.
func Redact(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	out := make([]string, len(argv))
	hide := false // previous arg was a secret flag awaiting its value
	for i, a := range argv {
		switch {
		case hide:
			out[i], hide = "***", false
		case i > 0 && isSecretPair(a):
			k, _, _ := strings.Cut(a, "=")
			out[i] = k + "=***"
		case i > 0 && isSecretFlag(a):
			out[i], hide = a, true
		case i > 0 && knownToken.MatchString(a):
			out[i] = "***"
		default:
			out[i] = redactURL(a)
		}
	}
	return out
}

var (
	secretName = regexp.MustCompile(`(?i)(^|[-_.])(token|secret|key|apikey|password|passwd|pass|auth|credentials?|cred)s?$`)
	knownToken = regexp.MustCompile(`^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|sk-|npm_|AKIA)[A-Za-z0-9_\-]{8,}$`)
)

func isSecretFlag(a string) bool {
	if !strings.HasPrefix(a, "-") || strings.Contains(a, "=") {
		return false
	}
	return secretName.MatchString(strings.TrimLeft(a, "-"))
}

func isSecretPair(a string) bool {
	k, v, ok := strings.Cut(a, "=")
	if !ok || v == "" || strings.Contains(k, "://") {
		return false
	}
	return secretName.MatchString(strings.TrimLeft(k, "-"))
}

func redactURL(a string) string {
	if !strings.Contains(a, "://") || !strings.Contains(a, "@") {
		return a
	}
	u, err := url.Parse(a)
	if err != nil || u.User == nil {
		return a
	}
	if _, has := u.User.Password(); !has {
		return a
	}
	u.User = url.User(u.User.Username())
	return strings.Replace(u.String(), "@", ":***@", 1) // the first @ ends the userinfo
}
