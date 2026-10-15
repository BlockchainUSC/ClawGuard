package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Upstream forwards a request to the LLM provider.
//
// The gateway holds the provider key; the client's own credential never leaves
// this process. That is what makes the gateway a trust boundary rather than a
// suggestion — a client that routes around it has no key to use.
type Upstream struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// UpstreamResponse is the provider's answer, read into memory.
//
// Buffered rather than streamed because v1 rejects streaming outright; see the
// Decisions section of README.md. When streaming returns, this is the type that
// grows an incremental form.
type UpstreamResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// hopByHopHeaders are connection-scoped and must not be forwarded by a proxy
// (RFC 7230 §6.1). Copying them through produces subtle, hard-to-trace failures
// — a Connection: close from upstream closing the client's keep-alive, or a
// Transfer-Encoding that no longer describes the body we are sending.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Forward sends req upstream and returns the raw response.
//
// The upstream status and body are returned as-is rather than being
// re-interpreted: a 429 from the provider is the client's problem to handle,
// and a gateway that translates it into its own error shape makes every
// upstream failure look like a gateway failure.
func (u *Upstream) Forward(ctx context.Context, req ChatRequest) (*UpstreamResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("re-serialising request: %w", err)
	}

	url := strings.TrimRight(u.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building upstream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if u.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+u.APIKey)
	}

	resp, err := u.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading upstream response: %w", err)
	}

	out := &UpstreamResponse{Status: resp.StatusCode, Header: http.Header{}, Body: raw}
	for k, vs := range resp.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	return out, nil
}
