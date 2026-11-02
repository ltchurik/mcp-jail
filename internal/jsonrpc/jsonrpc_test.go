package jsonrpc

import (
	"strings"
	"testing"
)

func TestParseStrictKeys(t *testing.T) {
	bad := map[string]string{
		"case variant method": `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{}}`,
		"case variant params": `{"jsonrpc":"2.0","id":1,"method":"tools/call","PARAMS":{}}`,
		"case variant id":     `{"jsonrpc":"2.0","ID":1,"method":"ping"}`,
		"duplicate method":    `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}`,
		"batch":               `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		"two objects":         `{"jsonrpc":"2.0","id":1,"method":"ping"} {"jsonrpc":"2.0","id":2,"method":"ping"}`,
		"trailing garbage":    `{"jsonrpc":"2.0","id":1,"method":"ping"} x`,
		"scalar":              `"ping"`,
		"method and result":   `{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}`,
		"object id":           `{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`,
		"array id":            `{"jsonrpc":"2.0","id":[1],"method":"ping"}`,
		"bool id":             `{"jsonrpc":"2.0","id":true,"method":"ping"}`,
		"long s":              `{"jsonrpc":"2.0","id":1,"method":"ping","paramſ":{}}`, // U+017F folds to "s": encoding/json would read it as params
	}
	for name, line := range bad {
		if m, err := Parse([]byte(line)); err == nil {
			t.Errorf("%s: accepted as %+v", name, m)
		}
	}
	good := []string{
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":"a","method":"ping","params":{"x":1},"extra":{"Method":"nope"}}`, // unknown keys are fine
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"result":null}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`,
	}
	for _, line := range good {
		if _, err := Parse([]byte(line)); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

func TestIDKeyCanonical(t *testing.T) {
	same := []string{`7`, `7.0`, `7e0`, `  7 `, `7E0`, `70e-1`}
	for _, id := range same[1:] {
		a, _ := Parse([]byte(`{"jsonrpc":"2.0","id":` + same[0] + `,"method":"ping"}`))
		b, _ := Parse([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"ping"}`))
		if b == nil || a.IDKey() != b.IDKey() {
			t.Errorf("id %s: key %q, want %q", id, b.IDKey(), a.IDKey())
		}
	}
	distinct := []string{`7`, `"7"`, `8`, `null`, `"seven"`, `7.5`}
	keys := map[string]string{}
	for _, id := range distinct {
		m, err := Parse([]byte(`{"jsonrpc":"2.0","id":` + id + `,"result":{}}`))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if prev, dup := keys[m.IDKey()]; dup {
			t.Errorf("ids %s and %s share key %q", prev, id, m.IDKey())
		}
		keys[m.IDKey()] = id
	}
	if m, _ := Parse([]byte(`{"jsonrpc":"2.0","method":"x"}`)); m.IDKey() != "" {
		t.Errorf("notification key %q", m.IDKey())
	}
}

func TestParseToolCall(t *testing.T) {
	for _, bad := range []string{
		`{"name":"delete_everything","NAME":"read_file","arguments":{}}`,
		`{"name":"read_file","arguments":{},"Arguments":{"path":"/etc"}}`,
		`{"name":"a","name":"b"}`,
		`{"arguments":{}}`,
		`{"name":7}`,
		`[]`, `null`, ``,
	} {
		if tc, err := ParseToolCall([]byte(bad)); err == nil {
			t.Errorf("%s: accepted as %+v", bad, tc)
		}
	}
	tc, err := ParseToolCall([]byte(`{"name":"read_file","arguments":{"path":"/x"},"_meta":{"Name":"x"}}`))
	if err != nil || tc.Name != "read_file" || string(tc.Arguments) != `{"path":"/x"}` {
		t.Fatalf("%+v %v", tc, err)
	}
}

func TestNewErrorResponseNullID(t *testing.T) {
	if b := NewErrorResponse(nil, CodeInvalidRequest, "x"); !strings.Contains(string(b), `"id":null`) {
		t.Fatalf("%s", b)
	}
}
