package gateway

import (
	"bytes"
	"encoding/json"
	"io"
)

// mustJSONString encodes a Go string as a JSON string. The only way
// json.Marshal fails on a string is invalid UTF-8, which cannot occur for the
// compiled-in constants this is used with.
func mustJSONString(s string) json.RawMessage {
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return b
}

func stringsReader(b []byte) io.Reader { return bytes.NewReader(b) }
