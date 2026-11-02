package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultError(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		failed bool
	}{
		{`{"content":[{"type":"text","text":"ok"}]}`, "", false},
		{`{"content":[],"isError":false}`, "", false},
		{`{"content":[{"type":"text","text":"EROFS: read-only file system, open '/home/u/projects/app.py'\nstack..."}],"isError":true}`,
			"EROFS: read-only file system, open '/home/u/projects/app.py'", true},
		{`{"content":[{"type":"image","data":"x"}],"isError":true}`, "isError", true},
		{`{"isError":true}`, "isError", true},
		{`not json`, "", false},
	}
	for _, c := range cases {
		msg, failed := resultError(json.RawMessage(c.in))
		if failed != c.failed || msg != c.want {
			t.Errorf("resultError(%s) = (%q, %v), want (%q, %v)", c.in, msg, failed, c.want, c.failed)
		}
	}
	long := `{"content":[{"type":"text","text":"` + strings.Repeat("x", 300) + `"}],"isError":true}`
	if msg, _ := resultError(json.RawMessage(long)); len([]rune(msg)) != 201 {
		t.Errorf("long message not trimmed: %d runes", len([]rune(msg)))
	}
}
