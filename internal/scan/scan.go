// Package scan holds the content heuristics mcp-jail applies to text a
// server chooses: tool, prompt and resource definitions, and later the
// results it returns. A finding is a hint for a human, never a verdict:
// the lock decides what is trusted, scan only says where to look first.
package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Finding is one suspicious place in a text.
type Finding struct {
	// Rule names the heuristic: hidden-unicode, hidden-markup, instruction,
	// sensitive-path, fetch-and-run, exfiltration, encoded, shadowing.
	Rule string `json:"rule"`
	// Where is the JSON path of the string inside the item ("description",
	// "inputSchema.properties.path.description"); "" for a bare text.
	Where string `json:"where,omitempty"`
	// Detail is what matched, shortened and made printable.
	Detail string `json:"detail"`
}

func (f Finding) String() string {
	if f.Where == "" {
		return f.Rule + " (" + f.Detail + ")"
	}
	return f.Where + ": " + f.Rule + " (" + f.Detail + ")"
}

// Rules lists every rule id, in report order.
var Rules = []string{"hidden-unicode", "hidden-markup", "instruction", "sensitive-path", "fetch-and-run", "exfiltration", "encoded", "shadowing"}

// Known reports whether id names a rule.
func Known(id string) bool {
	for _, r := range Rules {
		if r == id {
			return true
		}
	}
	return false
}

// ResultRules are the rules that make sense for content a server returns
// (a tool result, a resource, a prompt, a log message): a file that names
// ~/.ssh or carries base64 is ordinary data, text that addresses the model
// or hides from the reader is not.
var ResultRules = []string{"hidden-unicode", "hidden-markup", "instruction"}

// Options tune a scan.
type Options struct {
	// Only, when set, restricts the scan to these rules.
	Only []string
	// Ignore lists rule ids that are not reported.
	Ignore []string
	// Foreign maps tool names of other servers to the server that owns
	// them, for the shadowing rule; nil disables the rule.
	Foreign map[string]string
	// Own lists the names of this server's own items; a foreign name that
	// is also an own name is not shadowing.
	Own map[string]bool
}

func (o Options) ignored(rule string) bool {
	for _, i := range o.Ignore {
		if i == rule {
			return true
		}
	}
	if o.Only == nil {
		return false
	}
	for _, r := range o.Only {
		if r == rule {
			return false
		}
	}
	return true
}

// pattern is one regular expression under a rule.
type pattern struct {
	rule string
	re   *regexp.Regexp
}

var patterns = []pattern{
	// markup a model reads and a human skims past
	{"hidden-markup", regexp.MustCompile(`(?i)<!--`)},
	{"hidden-markup", regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|hidden|secret|assistant|context|rules?|note_to_(ai|model|assistant))\b[^>]*>`)},
	{"hidden-markup", regexp.MustCompile(`<\|[a-zA-Z_]+\|>`)},
	{"hidden-markup", regexp.MustCompile(`\[/?INST\]|<<SYS>>`)},
	// text addressed to the model rather than to the user
	{"instruction", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding|other|system)\s+(instructions?|prompts?|rules?|messages?|context|guidance)`)},
	{"instruction", regexp.MustCompile(`(?i)\b(do not|don'?t|never|without)\s+(tell|telling|inform|informing|mention|mentioning|reveal|revealing|disclose|disclosing|show|showing|notify|notifying|alert|alerting|warn|warning|let|letting)\b[^.\n]{0,40}\b(user|human|operator|person)\b`)},
	{"instruction", regexp.MustCompile(`(?i)\b(do not|don'?t|never|no need to|skip|without)\s+(ask|asking|request|requesting|wait|waiting|check|checking)\s+(for\s+)?(the\s+user'?s?\s+)?(permission|confirmation|approval|consent)`)},
	{"instruction", regexp.MustCompile(`(?i)\b(before|prior to)\s+(calling|using|invoking|running|executing)\s+(this|any|the|another|each|every)\s+(tool|function|command)`)},
	{"instruction", regexp.MustCompile(`(?i)\bpass\s+(it|them|its?\s+contents?|the\s+contents?|the\s+result|the\s+output)\s+(as|in|to|via|along|through)\b`)},
	{"instruction", regexp.MustCompile(`(?i)\b(this is|these are)\s+(a\s+|an\s+)?(system|hidden|secret|internal|confidential|private)\s+(message|instruction|note|prompt)`)},
	{"instruction", regexp.MustCompile(`(?i)\bsystem\s+prompt\b|\bdeveloper\s+message\b`)},
	{"instruction", regexp.MustCompile(`(?i)\bkeep\s+(this|it|that)\s+(a\s+)?(secret|hidden|confidential|private|between us)`)},
	{"instruction", regexp.MustCompile(`(?i)\b(include|send|attach|append|forward|copy|paste|insert)\b[^.\n]{0,30}\b(conversation|chat|prompt|message)s?\s+(history|context|transcript|so far)`)},
	{"instruction", regexp.MustCompile(`(?i)\b(include|send|append|attach|paste|pass|insert|put|forward|copy|read|add)\b[^.\n]{0,40}\b(api[_ -]?keys?|passwords?|private\s+keys?|secrets?|access\s+tokens?|auth\s+tokens?|credentials?)\b`)},
	// files a weather server has no business naming
	{"sensitive-path", regexp.MustCompile(`(?i)(^|[\s"'` + "`" + `(/])\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b`)},
	{"sensitive-path", regexp.MustCompile(`(?i)\.aws/(credentials|config)|\.netrc\b|\.npmrc\b|\.pypirc\b|\.gnupg\b|\.password-store\b|\.kube/config|\.docker/config\.json|\.git-credentials\b|\.(bash|zsh|sh)_history\b|\.config/gh/hosts\.yml|\bcredentials\.json\b`)},
	{"sensitive-path", regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)\b|/proc/self/environ\b|\bwallet\.dat\b|\b(login\.)?keychain(-db)?\b`)},
	{"sensitive-path", regexp.MustCompile(`(?i)(^|[\s"'` + "`" + `(/])\.env(\.[a-z]+)?\b`)},
	// code or content fetched at run time
	{"fetch-and-run", regexp.MustCompile(`(?i)\b(curl|wget|fetch|download|install|update|upgrade|run|execute|exec|eval|source|pip\s+install|npm\s+(i|install)|npx|uvx)\b[^.\n]{0,60}https?://`)},
	{"fetch-and-run", regexp.MustCompile(`(?i)https?://\S+[^.\n]{0,60}\b(and\s+)?(install|update|upgrade|run|execute|exec|eval|source)\s+(it|them|the\s+script|the\s+file|the\s+result)\b`)},
	{"fetch-and-run", regexp.MustCompile(`(?i)\bcurl\b[^|\n]{0,120}\|\s*(ba|z|da)?sh\b`)},
	{"fetch-and-run", regexp.MustCompile(`(?i)\b(auto|self)[- ]?updat(e|es|ed|ing|er)\b`)},
	// data told to leave
	{"exfiltration", regexp.MustCompile(`(?i)\b(send|upload|post|forward|transmit|email|exfiltrate|submit|report)\s+[^.\n]{0,60}?\b(to|at)\s+(https?://\S+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})`)},
	// a blob a human cannot read
	{"encoded", regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,2}`)},
}

// Text scans one string with every rule but shadowing.
func Text(s string, o Options) []Finding {
	var out []Finding
	if !o.ignored("hidden-unicode") {
		if d := hiddenUnicode(s); d != "" {
			out = append(out, Finding{Rule: "hidden-unicode", Detail: d})
		}
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		if seen[p.rule] || o.ignored(p.rule) {
			continue
		}
		if m := p.re.FindString(s); m != "" {
			seen[p.rule] = true
			out = append(out, Finding{Rule: p.rule, Detail: short(m)})
		}
	}
	if len(o.Foreign) > 0 && !o.ignored("shadowing") {
		if d := shadowing(s, o); d != "" {
			out = append(out, Finding{Rule: "shadowing", Detail: d})
		}
	}
	return out
}

// Item scans every string value of one JSON item (a tool, prompt or
// resource definition) and reports where each finding sits.
func Item(raw json.RawMessage, o Options) []Finding {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []Finding{{Rule: "hidden-markup", Detail: "item is not valid JSON"}}
	}
	var out []Finding
	walk(v, "", func(where, s string) {
		for _, f := range Text(s, o) {
			f.Where = where
			out = append(out, f)
		}
	})
	return out
}

// MaxResult bounds what Result scans; a larger result is reported as
// unscanned rather than parsed.
const MaxResult = 4 << 20

// Result scans every string of a result or notification the server
// returned with ResultRules (narrowed further by o). It returns at most
// limit findings and ok=false when the payload could not be scanned (too
// large or not JSON), which a fail-closed caller treats as a finding.
func Result(raw json.RawMessage, o Options, limit int) (findings []Finding, ok bool) {
	if len(raw) > MaxResult {
		return []Finding{{Rule: "unscanned", Detail: fmt.Sprintf("%d bytes, more than the %d the lint reads", len(raw), MaxResult)}}, false
	}
	if o.Only == nil {
		o.Only = ResultRules
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []Finding{{Rule: "unscanned", Detail: "not valid JSON"}}, false
	}
	walk(v, "", func(where, s string) {
		if len(findings) > limit {
			return
		}
		for _, f := range Text(s, o) {
			f.Where = where
			findings = append(findings, f)
		}
	})
	if len(findings) > limit {
		findings = append(findings[:limit], Finding{Rule: "more", Detail: fmt.Sprintf("%d further finding(s)", len(findings)-limit)})
	}
	return findings, true
}

// walk calls fn for every string in v with its dotted path.
func walk(v any, where string, fn func(where, s string)) {
	switch t := v.(type) {
	case string:
		fn(where, t)
	case []any:
		for i, e := range t {
			walk(e, fmt.Sprintf("%s[%d]", where, i), fn)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if where != "" {
				p = where + "." + k
			}
			walk(t[k], p, fn)
		}
	}
}

// hiddenUnicode names the invisible or direction-changing code points in
// s, grouped, so that "U+200B zero width space ×3" reads at a glance.
func hiddenUnicode(s string) string {
	counts := map[rune]int{}
	var order []rune
	for _, r := range s {
		if !hidden(r) {
			continue
		}
		if counts[r] == 0 {
			order = append(order, r)
		}
		counts[r]++
	}
	if len(order) == 0 {
		return ""
	}
	parts := make([]string, 0, len(order))
	for i, r := range order {
		if i == 4 {
			parts = append(parts, fmt.Sprintf("and %d more", len(order)-4))
			break
		}
		p := fmt.Sprintf("U+%04X %s", r, runeName(r))
		if counts[r] > 1 {
			p += fmt.Sprintf(" ×%d", counts[r])
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

func hidden(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case r < 0x20 || r == 0x7f: // C0 controls
		return true
	case r >= 0x80 && r <= 0x9f: // C1 controls
		return true
	case r == 0x200b || r == 0x200c || r == 0x200d || r == 0x2060 || r == 0xfeff || r == 0x180e: // zero width
		return true
	case r == 0x200e || r == 0x200f || r == 0x061c || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069): // bidi
		return true
	case r >= 0xe0000 && r <= 0xe007f: // tags
		return true
	case unicode.Is(unicode.Co, r): // private use
		return true
	}
	return false
}

func runeName(r rune) string {
	switch {
	case r == 0x200b:
		return "zero width space"
	case r == 0x200c || r == 0x200d:
		return "zero width joiner"
	case r == 0x2060:
		return "word joiner"
	case r == 0xfeff:
		return "byte order mark"
	case r == 0x180e:
		return "mongolian vowel separator"
	case r == 0x200e || r == 0x200f || r == 0x061c || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
		return "bidi control"
	case r >= 0xe0000 && r <= 0xe007f:
		return "tag character"
	case unicode.Is(unicode.Co, r):
		return "private use"
	}
	return "control character"
}

// shadowing reports tool names of other servers that s mentions as whole
// words. Short or plain names (fetch, search) are skipped: only a name with
// a separator or camelCase is distinctive enough to mean a specific tool.
func shadowing(s string, o Options) string {
	names := make([]string, 0, len(o.Foreign))
	for n := range o.Foreign {
		if len(n) >= 5 && distinctive(n) && !o.Own[n] && strings.Contains(s, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	var hits []string
	for _, n := range names {
		re, err := regexp.Compile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(n) + `($|[^A-Za-z0-9_])`)
		if err != nil || !re.MatchString(s) {
			continue
		}
		hits = append(hits, fmt.Sprintf("%s of %s", n, o.Foreign[n]))
		if len(hits) == 3 {
			break
		}
	}
	return strings.Join(hits, ", ")
}

func distinctive(n string) bool {
	if strings.ContainsAny(n, "_-.") {
		return true
	}
	prev := rune(0)
	for _, r := range n {
		if unicode.IsUpper(r) && unicode.IsLower(prev) {
			return true
		}
		prev = r
	}
	return false
}

// short makes a match printable and at most 80 bytes.
func short(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || hidden(r) {
			return '?'
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		cut := 80
		for cut > 0 && (s[cut]&0xc0) == 0x80 {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}
