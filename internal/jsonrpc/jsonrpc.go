// Package jsonrpc holds a minimal, allocation-light view of JSON-RPC 2.0
// messages as used by the Model Context Protocol over stdio.
package jsonrpc

import (
	"encoding/json"
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

	Raw []byte `json:"-"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Parse decodes one line of JSON-RPC. The original bytes are kept in Raw.
func Parse(line []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, err
	}
	m.Raw = line
	return &m, nil
}

// IsRequest reports whether the message is a request (has id and method).
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports whether the message is a notification (method, no id).
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// IsResponse reports whether the message is a response (id, no method).
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// IDKey returns a stable string key for the id, for correlating responses.
func (m *Message) IDKey() string { return string(m.ID) }

// NewErrorResponse builds an error response for the given id.
func NewErrorResponse(id json.RawMessage, code int, msg string) []byte {
	b, _ := json.Marshal(Message{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: msg},
	})
	return b
}

// MCP-level error codes used by mcp-jail. -32000..-32099 is the reserved
// server error range in JSON-RPC 2.0.
const (
	CodePolicyDenied = -32001
	CodeRugPull      = -32002
	CodeAskRejected  = -32003
)

// ToolCallParams is the params shape of a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolsListResult is the result shape of a tools/list response.
type ToolsListResult struct {
	Tools []json.RawMessage `json:"tools"`
}
