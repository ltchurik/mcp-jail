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

	"github.com/ltchurik/mcp-jail/internal/control"
	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
)

// webhookRequest is what mcp-jail POSTs for an `ask` decision.
type webhookRequest struct {
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Time      time.Time       `json:"ts"`
	// Note says why the call is asked about beyond the rule, e.g. a
	// credential in the arguments; empty otherwise.
	Note string `json:"note,omitempty"`
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

// webhookClient never follows redirects: the configured headers (tokens)
// go to the configured URL only, and a 3xx is not a decision.
var webhookClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// askHeadless decides an `ask` without a terminal. Two sources can answer:
// the webhook, when configured, and an attached dashboard (one that polled
// the control socket in the last few seconds). With neither, the call is
// denied at once, as before. Otherwise the first decision wins; a webhook
// that fails to produce a decision (Slack's "ok", a 500, a timeout) leaves
// the dashboard until the deadline, and the deadline is a deny.
func (p *Proxy) askHeadless(tc jsonrpc.ToolCallParams, note string) (bool, string) {
	wh := p.rules().Ask.Webhook.URL != ""
	attached := p.Asks != nil && p.Asks.Attached()
	if !wh && !attached {
		return false, "no tty"
	}
	timeout := p.rules().Ask.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if wh && (!attached || p.rules().Ask.Webhook.Timeout > timeout) {
		timeout = p.rules().Ask.Webhook.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		ok     bool
		reason string
		final  bool
	}
	whc := make(chan result, 1)
	if wh {
		go func() {
			ok, reason, final := p.askWebhook(ctx, tc, note)
			whc <- result{ok, reason, final}
		}()
	} else {
		whc = nil
	}
	dc := make(chan control.Decision, 1)
	if p.Asks != nil {
		pend := p.Asks.Submit(tc.Name, tc.Arguments, time.Now().Add(timeout))
		defer p.Asks.Remove(pend.ID)
		go func() {
			if d, ok := pend.Wait(ctx); ok {
				dc <- d
			}
		}()
	}
	whReason := ""
	for {
		select {
		case r := <-whc:
			if r.final || !attached {
				return r.ok, r.reason
			}
			whReason = r.reason // keep waiting for the dashboard
			whc = nil
		case d := <-dc:
			if d.Allow {
				return true, d.By
			}
			return false, d.By
		case <-ctx.Done():
			reason := fmt.Sprintf("no answer within %s", timeout)
			switch {
			case whReason != "":
				reason = whReason + "; " + reason
			case wh:
				reason = "webhook: " + reason
			}
			return false, reason
		}
	}
}

// askWebhook asks the configured endpoint. Every failure mode is a deny; the
// returned string is the audit reason. final is true for an explicit allow
// or deny, false when the endpoint produced no decision.
func (p *Proxy) askWebhook(ctx context.Context, tc jsonrpc.ToolCallParams, note string) (ok bool, reason string, final bool) {
	w := p.rules().Ask.Webhook
	args := string(tc.Arguments)
	if len(args) > 400 {
		args = args[:400] + "…"
	}
	text := fmt.Sprintf("[mcp-jail] %s wants to call %s %s", p.Policy.Name, tc.Name, args)
	if note != "" {
		text += " (" + note + ")"
	}
	body, err := json.Marshal(webhookRequest{
		Server: p.Policy.Name, Tool: tc.Name, Arguments: tc.Arguments, Time: time.Now().UTC(), Note: note,
		Text: text,
	})
	if err != nil {
		return false, "webhook: encode: " + err.Error(), false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return false, "webhook: " + err.Error(), false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mcp-jail")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}
	resp, err := webhookClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Sprintf("webhook: no answer within %s", w.Timeout), false
		}
		return false, "webhook: " + oneLine(err.Error()), false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("webhook: status %d", resp.StatusCode), false
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxWebhookBody))
	if err != nil {
		return false, "webhook: read: " + err.Error(), false
	}
	var ans webhookResponse
	if err := json.Unmarshal(raw, &ans); err != nil {
		return false, "webhook: response is not a decision", false
	}
	switch ans.Decision {
	case "allow":
		return true, "webhook", true
	case "deny":
		if ans.Reason != "" {
			return false, "webhook: " + oneLine(ans.Reason), true
		}
		return false, "webhook", true
	}
	return false, "webhook: response is not a decision", false
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
