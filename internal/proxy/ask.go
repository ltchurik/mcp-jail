package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
)

// webhookRequest is what mcp-jail POSTs for an `ask` decision.
type webhookRequest struct {
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Time      time.Time       `json:"ts"`
	// Text is a one-line human summary so that chat webhooks (Slack, Mattermost,
	// Discord-compatible) show something useful.
	Text string `json:"text"`
}

// webhookResponse is the only answer that allows: {"decision":"allow"}.
type webhookResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

const maxWebhookBody = 64 << 10

// askWebhook asks the configured endpoint. Every failure mode is a deny; the
// returned string is the audit reason.
func (p *Proxy) askWebhook(tc jsonrpc.ToolCallParams) (bool, string) {
	w := p.Policy.Ask.Webhook
	args := string(tc.Arguments)
	if len(args) > 400 {
		args = args[:400] + "…"
	}
	body, err := json.Marshal(webhookRequest{
		Server: p.Policy.Name, Tool: tc.Name, Arguments: tc.Arguments, Time: time.Now().UTC(),
		Text: fmt.Sprintf("[mcp-jail] %s wants to call %s %s", p.Policy.Name, tc.Name, args),
	})
	if err != nil {
		return false, "webhook: encode: " + err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return false, "webhook: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mcp-jail")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, fmt.Sprintf("webhook: no answer within %s", w.Timeout)
		}
		return false, "webhook: " + oneLine(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("webhook: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxWebhookBody))
	if err != nil {
		return false, "webhook: read: " + err.Error()
	}
	var ans webhookResponse
	if err := json.Unmarshal(raw, &ans); err != nil {
		return false, "webhook: response is not a decision"
	}
	switch ans.Decision {
	case "allow":
		return true, "webhook"
	case "deny":
		if ans.Reason != "" {
			return false, "webhook: " + oneLine(ans.Reason)
		}
		return false, "webhook"
	}
	return false, "webhook: response is not a decision"
}

func oneLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
