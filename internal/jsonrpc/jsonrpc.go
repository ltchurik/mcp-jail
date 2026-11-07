// Package jsonrpc holds a minimal, allocation-light view of JSON-RPC 2.0
// messages as used by the Model Context Protocol over stdio.
//
// Parsing is strict where the proxy's decisions depend on it: a message
// must be a single object, the keys the proxy reads must be spelled exactly
// once with exact case (encoding/json would otherwise match "Method" or
// "NAME" case-insensitively and let a client smuggle a second value past
// the policy to a server that reads only the exact key), and ids are
// reduced to a canonical form so a server cannot answer request 7 as 7.0
// and slip past the lock.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Message is a loosely typed JSON-RPC 2.0 envelope. Unknown fields are
// preserved in Raw so the proxy can forward messages byte-for-byte.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`

	Raw   []byte `json:"-"`
	idKey string
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ErrNotObject is returned for a batch (array) or any non-object line.
var ErrNotObject = errors.New("jsonrpc: message is not a single object")

// envelopeKeys are the keys the proxy reads from the envelope.
var envelopeKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}

// Parse decodes one line of JSON-RPC. The original bytes are kept in Raw.
func Parse(line []byte) (*Message, error) {
	if err := CheckKeys(line, envelopeKeys...); err != nil {
		return nil, err
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, err
	}
	if m.Method != "" && (m.Result != nil || m.Error != nil) {
		return nil, errors.New("jsonrpc: message has both method and result/error")
	}
	k, err := canonicalID(m.ID)
	if err != nil {
		return nil, err
	}
	m.idKey = k
	m.Raw = line
	return &m, nil
}

// CheckKeys verifies that raw is a single JSON object in which each of the
// known keys appears at most once and, when it appears, is spelled exactly:
// a key that equals a known key only under case folding is refused. Other
// keys are ignored. It does not validate the values.
func CheckKeys(raw []byte, known ...string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrNotObject
	}
	seen := make(map[string]bool, len(known))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		for _, k := range known {
			if !strings.EqualFold(key, k) {
				continue
			}
			if key != k {
				return fmt.Errorf("jsonrpc: key %q: only %q is accepted", key, k)
			}
			if seen[k] {
				return fmt.Errorf("jsonrpc: key %q repeated", k)
			}
			seen[k] = true
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return err
	}
	if rest := bytes.TrimSpace(raw[dec.InputOffset():]); len(rest) != 0 {
		return errors.New("jsonrpc: trailing data after the object")
	}
	return nil
}

// canonicalID reduces an id to the key the proxy correlates on: numbers
// by value (7, 7.0 and 7e0 are the same request to every client), strings
// quoted, null as "null". Anything else is not a valid id.
func canonicalID(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", nil
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
		return strconv.Quote(s), nil
	case 'n':
		if string(raw) == "null" {
			return "null", nil
		}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		f, err := strconv.ParseFloat(string(raw), 64)
		if err != nil {
			return "", fmt.Errorf("jsonrpc: id %s: %w", raw, err)
		}
		return strconv.FormatFloat(f, 'g', -1, 64), nil
	}
	return "", fmt.Errorf("jsonrpc: id must be a string, a number or null, got %s", raw)
}

// IsRequest reports whether the message is a request (has id and method).
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports whether the message is a notification (method, no id).
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// IsResponse reports whether the message is a response (id, no method).
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// IDKey returns the canonical key of the id, for correlating responses.
func (m *Message) IDKey() string { return m.idKey }

// NewErrorResponse builds an error response for the given id.
func NewErrorResponse(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(Message{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: msg},
	})
	return b
}

// JSON-RPC 2.0 error codes the proxy answers with.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeInvalidParams  = -32602
)

// MCP-level error codes used by mcp-jail. -32000..-32099 is the reserved
// server error range in JSON-RPC 2.0.
const (
	CodePolicyDenied = -32001
	CodeRugPull      = -32002
	CodeAskRejected  = -32003
	CodeNoResponse   = -32004 // the server never answered and the request was dropped
	CodeRemote       = -32005 // a remote server could not be reached or answered with an HTTP error
	CodeLintRefused  = -32006 // the result failed lint.results: deny
	CodeLimit        = -32007 // a limits.* budget is spent
)

// ToolCallParams is the params shape of a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ParseToolCall decodes tools/call params strictly: an object whose name
// and arguments keys are exact and unique, with a non-empty string name.
func ParseToolCall(params json.RawMessage) (ToolCallParams, error) {
	var tc ToolCallParams
	if err := CheckKeys(params, "name", "arguments"); err != nil {
		return tc, err
	}
	if err := json.Unmarshal(params, &tc); err != nil {
		return tc, err
	}
	if tc.Name == "" {
		return tc, errors.New("tools/call: params.name missing or not a string")
	}
	return tc, nil
}

// ToolsListResult is the result shape of a tools/list response.
type ToolsListResult struct {
	Tools []json.RawMessage `json:"tools"`
}
