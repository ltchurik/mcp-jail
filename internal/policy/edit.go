package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SetRule writes `tools.rules[tool] = d` into the policy file at path,
// keeping every other line, comment and key order as they are. A rule that
// already exists is changed in place: the scalar form gets a new value, the
// mapping form (with args) gets a new `decision` and keeps its constraints.
// The result is validated before it replaces the file; a policy that would
// not load is never written (fail closed).
func SetRule(path, tool string, d Decision) error {
	if err := checkToolName(tool); err != nil {
		return err
	}
	if err := checkDecision(d); err != nil {
		return err
	}
	// A symlinked policy file is edited at its target, not turned into a
	// file. Edits of one directory are serialised, so two dashboards
	// promoting rules at once cannot lose each other's change.
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	unlock, err := lockDir(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("lock %s: %w", filepath.Dir(path), err)
	}
	defer unlock()
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	root := documentRoot(&doc)
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: top level is not a mapping", path)
	}
	tools := childMapping(root, "tools")
	rules := childMapping(tools, "rules")
	if v := mappingValue(rules, tool); v != nil {
		switch v.Kind {
		case yaml.ScalarNode:
			setScalar(v, string(d))
		case yaml.MappingNode:
			if dv := mappingValue(v, "decision"); dv != nil {
				setScalar(dv, string(d))
			} else {
				appendPair(v, "decision", string(d))
			}
		default:
			return fmt.Errorf("tools.rules[%s]: unexpected %v node", tool, v.Kind)
		}
	} else {
		appendPair(rules, tool, string(d))
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	// It must still be a valid policy, and the rule must have landed.
	p, err := parse(out.Bytes(), path)
	if err != nil {
		return fmt.Errorf("refusing to write: %w", err)
	}
	if r, ok := p.Tools.Rules[tool]; !ok || r.Decision != d {
		return fmt.Errorf("refusing to write: rule %q did not take (%+v)", tool, r)
	}
	return replaceFile(path, out.Bytes())
}

// checkToolName accepts tool names and the globs tools.rules allows:
// printable, no whitespace, bounded length.
func checkToolName(tool string) error {
	if tool == "" {
		return errors.New("tool: empty")
	}
	if len(tool) > 128 {
		return errors.New("tool: longer than 128 bytes")
	}
	for _, r := range tool {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("tool %q: control or whitespace character", tool)
		}
	}
	return nil
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
		}
		return doc.Content[0]
	}
	if doc.Kind == 0 { // empty file
		*doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
		return doc.Content[0]
	}
	return doc
}

// mappingValue returns the value node for key, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// childMapping returns m[key] as a mapping, creating it when missing or
// null. A flow-style parent ({ a: b }) keeps its style.
func childMapping(m *yaml.Node, key string) *yaml.Node {
	v := mappingValue(m, key)
	if v == nil {
		v = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: m.Style & yaml.FlowStyle}
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
		return v
	}
	if v.Kind == yaml.ScalarNode && (v.Tag == "!!null" || v.Value == "") {
		*v = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: m.Style & yaml.FlowStyle, HeadComment: v.HeadComment, LineComment: v.LineComment, FootComment: v.FootComment}
	}
	return v
}

func appendPair(m *yaml.Node, key, value string) {
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	if strings.ContainsAny(key, "*?[]{}:#,&!|>'\"%@`") || key != strings.TrimSpace(key) {
		k.Style = yaml.DoubleQuotedStyle
	}
	m.Content = append(m.Content, k, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func setScalar(n *yaml.Node, value string) {
	n.Tag, n.Value, n.Style = "!!str", value, 0
}

// replaceFile writes b over path atomically, keeping the file mode.
func replaceFile(path string, b []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LiteralTool escapes the glob metacharacters of filepath.Match so the
// returned pattern matches exactly tool and nothing else.
func LiteralTool(tool string) string {
	if !strings.ContainsAny(tool, "*?[\\") {
		return tool
	}
	var b strings.Builder
	for _, r := range tool {
		switch r {
		case '*', '?', '[', '\\':
			b.WriteString("[" + string(r) + "]")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
