// Package gateway is the reverse proxy that sits between a client and an LLM
// provider, applying the capability model to each request.
package gateway

import (
	"encoding/json"
	"fmt"
	"strings"

	"openclaw/guard/overseer/internal/inspect"
)

// ChatRequest is an OpenAI-compatible chat completion request.
//
// Only the fields the gateway reasons about are modelled. Everything else is
// kept verbatim in `extra` and written back out untouched, because a proxy that
// silently drops a parameter it does not recognise is worse than one that
// refuses to parse: the caller gets a plausible answer computed from different
// settings than they asked for.
//
// Parsing rather than forwarding bytes is deliberate. Phase 5 has to rewrite
// the tools array, and retrofitting that into a byte-copying proxy means
// touching every path. The cost of doing it now is that "transparent" means
// semantically identical rather than byte identical.
type ChatRequest struct {
	Model    string    `json:"-"`
	Messages []Message `json:"-"`
	Tools    []Tool    `json:"-"`
	Stream   bool      `json:"-"`

	extra map[string]json.RawMessage
}

// Message is one turn. Content is left raw because the OpenAI schema allows
// either a string or an array of typed parts, and the gateway only ever needs
// the text for inspection — see Text.
type Message struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content,omitempty"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	Name       string          `json:"name,omitempty"`
}

// Text extracts the human-readable content of a message, flattening the
// multi-part form. Anything it cannot interpret yields the empty string rather
// than an error: inspection on a best-effort rendering is better than refusing
// a request because a provider added a content part type.
func (m Message) Text() string {
	if len(m.Content) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(m.Content, &parts); err != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Text != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// Tool is a tool offered to the model.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ToolCall is a call the model asked for.
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// reservedKeys are the fields ChatRequest models explicitly. Everything else
// round-trips through extra.
var reservedKeys = []string{"model", "messages", "tools", "stream"}

func (r *ChatRequest) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("request body is not a JSON object: %w", err)
	}

	if v, ok := raw["model"]; ok {
		if err := json.Unmarshal(v, &r.Model); err != nil {
			return fmt.Errorf("field \"model\": %w", err)
		}
	}
	if v, ok := raw["messages"]; ok {
		if err := json.Unmarshal(v, &r.Messages); err != nil {
			return fmt.Errorf("field \"messages\": %w", err)
		}
	}
	if v, ok := raw["tools"]; ok {
		if err := json.Unmarshal(v, &r.Tools); err != nil {
			return fmt.Errorf("field \"tools\": %w", err)
		}
	}
	if v, ok := raw["stream"]; ok {
		if err := json.Unmarshal(v, &r.Stream); err != nil {
			return fmt.Errorf("field \"stream\": %w", err)
		}
	}

	for _, k := range reservedKeys {
		delete(raw, k)
	}
	r.extra = raw
	return nil
}

func (r ChatRequest) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(r.extra)+len(reservedKeys))
	for k, v := range r.extra {
		out[k] = v
	}

	put := func(key string, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("field %q: %w", key, err)
		}
		out[key] = b
		return nil
	}

	if err := put("model", r.Model); err != nil {
		return nil, err
	}
	if err := put("messages", r.Messages); err != nil {
		return nil, err
	}
	// Omitted rather than written as null: an empty tools array is a different
	// instruction to a provider than no tools field at all, and phase 5 depends
	// on being able to express both.
	if r.Tools != nil {
		if err := put("tools", r.Tools); err != nil {
			return nil, err
		}
	}
	if r.Stream {
		if err := put("stream", r.Stream); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}

// LastUserText returns the most recent user message, which is what inbound
// inspection judges.
func (r ChatRequest) LastUserText() string {
	for i := len(r.Messages) - 1; i >= 0; i-- {
		if r.Messages[i].Role == "user" {
			return r.Messages[i].Text()
		}
	}
	return ""
}

// PriorUserText returns the user's earlier turns, oldest first, excluding the
// most recent one.
//
// It is the baseline for "is this message unusually large". Only user turns
// count: the question is how long this person's messages normally are, and
// mixing in the model's replies would measure something else entirely. The
// latest turn is excluded because it is the thing being compared.
func (r ChatRequest) PriorUserText() []string {
	latest := -1
	for i := len(r.Messages) - 1; i >= 0; i-- {
		if r.Messages[i].Role == "user" {
			latest = i
			break
		}
	}
	if latest <= 0 {
		return nil
	}

	var out []string
	for _, m := range r.Messages[:latest] {
		if m.Role == "user" {
			out = append(out, m.Text())
		}
	}
	return out
}

// ConversationBefore returns every turn preceding the latest user message,
// oldest first, with roles intact.
//
// The latest user turn is excluded because it is the thing being judged; this
// is the context it is judged against. Roles are kept because a classifier
// reading only the user's words cannot see an attack spread across turns.
func (r ChatRequest) ConversationBefore() []inspect.Turn {
	latest := -1
	for i := len(r.Messages) - 1; i >= 0; i-- {
		if r.Messages[i].Role == "user" {
			latest = i
			break
		}
	}
	if latest <= 0 {
		return nil
	}

	out := make([]inspect.Turn, 0, latest)
	for _, m := range r.Messages[:latest] {
		out = append(out, inspect.Turn{Role: m.Role, Text: m.Text()})
	}
	return out
}

// ToolNames lists the tools offered, in order.
func (r ChatRequest) ToolNames() []string {
	if len(r.Tools) == 0 {
		return nil
	}
	names := make([]string, 0, len(r.Tools))
	for _, t := range r.Tools {
		names = append(names, t.Function.Name)
	}
	return names
}
