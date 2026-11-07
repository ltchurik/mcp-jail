package scan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecrets(t *testing.T) {
	env := EnvSecrets([]string{"PATH=/usr/bin", "GITHUB_TOKEN=ghp_short", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "HOME=/home/u", "DB_PASSWORD=correct-horse-battery", "SHORT_TOKEN=abc"})
	if len(env) != 2 || env["AWS_SECRET_ACCESS_KEY"] == "" || env["DB_PASSWORD"] == "" {
		t.Fatalf("EnvSecrets = %v", env)
	}
	cases := []struct {
		args string
		want string // "where: rule (detail)" lines joined by \n
	}{
		{`{"path":"/home/u/notes.txt","query":"weather in Paris"}`, ""},
		{`{"text":"The AKIAIOSFODNN7EXAMPLE key was rotated"}`, "text: aws-access-key (20 bytes)"},
		{`{"body":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..."}`, "body: private-key (35 bytes)"},
		{`{"h":{"Authorization":"Bearer abcdefghijklmnopqrstuvwxyz0123"}}`, "h.Authorization: bearer (37 bytes)"},
		{`{"t":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}`, "t: github-token (40 bytes)"},
		{`{"t":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}`, "t: jwt (92 bytes)"},
		{`{"cfg":"password = hunter2hunter2"}`, "cfg: password-assignment (25 bytes)"},
		{`{"u":"https://user:s3cretpass@db.example/x"}`, "u: basic-auth-url (24 bytes)"},
		{`{"k":"sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}`, "k: openai-key (39 bytes)\nk: anthropic-key (39 bytes)"},
		{`{"note":"deploy with wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY please"}`, "note: env-value (value of $AWS_SECRET_ACCESS_KEY)"},
		{`{"list":["ok","correct-horse-battery"]}`, "list[1]: env-value (value of $DB_PASSWORD)"},
		{`null`, ""},
		{``, ""},
	}
	for _, c := range cases {
		fs := Secrets(json.RawMessage(c.args), SecretOptions{Env: env})
		var got []string
		for _, f := range fs {
			got = append(got, f.String())
		}
		if strings.Join(got, "\n") != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.args, strings.Join(got, "\n"), c.want)
		}
	}
	// a detail never carries the value
	for _, f := range Secrets(json.RawMessage(`{"t":"AKIAIOSFODNN7EXAMPLE"}`), SecretOptions{}) {
		if strings.Contains(f.Detail, "AKIA") {
			t.Fatalf("value leaked: %v", f)
		}
	}
	if fs := Secrets(json.RawMessage(`{"t":"AKIAIOSFODNN7EXAMPLE"}`), SecretOptions{Ignore: []string{"aws-access-key"}}); len(fs) != 0 {
		t.Fatalf("ignore: %v", fs)
	}
	if len(SecretRules) != len(secretPatterns)+1 || SecretRules[len(SecretRules)-1] != "env-value" {
		t.Fatal(SecretRules)
	}
}
