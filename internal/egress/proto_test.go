package egress

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadHeader(t *testing.T) {
	good := map[string]Request{
		"CONNECT api.github.com 443\n":   {Verb: "CONNECT", Host: "api.github.com", Port: 443},
		"CONNECT 127.0.0.1 8080\r\n":     {Verb: "CONNECT", Host: "127.0.0.1", Port: 8080},
		"DNS evil.example blocked\n":     {Verb: "DNS", Host: "evil.example", Decision: "blocked"},
		"CONNECT [::1] 443\n":            {Verb: "CONNECT", Host: "[::1]", Port: 443},
		"CONNECT x_y.internal.corp 80\n": {Verb: "CONNECT", Host: "x_y.internal.corp", Port: 80},
	}
	for in, want := range good {
		got, err := readHeader(bufio.NewReader(strings.NewReader(in)))
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v; want %+v", in, got, err, want)
		}
	}
	bad := []string{
		"", "CONNECT\n", "CONNECT host\n", "CONNECT host 0\n", "CONNECT host 70000\n",
		"CONNECT host abc\n", "GET host 80\n", "DNS host maybe\n", "CONNECT a/b 80\n",
		"CONNECT host 80", // no newline
		"CONNECT " + strings.Repeat("a", 300) + " 80\n",
		"CONNECT ho st 80\n", "CONNECT host 80 extra\n", "CONNECT host\x00 80\n",
	}
	for _, in := range bad {
		if _, err := readHeader(bufio.NewReader(strings.NewReader(in))); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
	if s := (Request{Verb: "CONNECT", Host: "h", Port: 1}).String(); s != "CONNECT h 1\n" {
		t.Errorf("String() = %q", s)
	}
}

func TestReadStatus(t *testing.T) {
	if err := readStatus(bufio.NewReader(strings.NewReader("OK\n"))); err != nil {
		t.Fatal(err)
	}
	err := readStatus(bufio.NewReader(strings.NewReader("ERR host not in network.allow: x\n")))
	if err == nil || !strings.Contains(err.Error(), "network.allow") {
		t.Fatalf("got %v", err)
	}
	if err := readStatus(bufio.NewReader(strings.NewReader("YES\n"))); err == nil {
		t.Fatal("garbage status must fail")
	}
}
