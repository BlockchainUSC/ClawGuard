package gateway

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ChatResponse is the OpenAI-compatible response shape, modelled only as far as
// the gateway needs to construct one itself.
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// RefusalText is what a hard-blocked session receives. Pre-compiled on purpose:
// at tier 3 the upstream model is never contacted, so there is nothing to
// generate a refusal with.
const RefusalText = "This request was blocked by a policy guardrail and was not sent to the model."

// StaticRefusal builds the tier-3 response.
//
// It is shaped as a normal, successful chat completion rather than an error,
// because the client asked a question and is getting an answer — the answer is
// a refusal. Returning an unparseable body or a bare HTTP error instead would
// crash SDKs that expect a completion, turning a deliberate block into what
// looks like a gateway fault.
//
// The request id is carried in the response id so a refusal can be traced back
// to its log line.
func StaticRefusal(model string, requestID uuid.UUID) ChatResponse {
	if model == "" {
		model = "openclaw-guard"
	}
	return ChatResponse{
		ID:      fmt.Sprintf("chatcmpl-guard-%s", requestID),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []Choice{{
			Index:        0,
			Message:      Message{Role: "assistant", Content: mustJSONString(RefusalText)},
			FinishReason: "stop",
		}},
		Usage: Usage{},
	}
}
