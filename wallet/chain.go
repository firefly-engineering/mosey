package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// chainJSON is the portable serialization of a delegation chain — the
// form `mosey grant` emits and `mosey attach` / the loopback authorizer
// consume. JSON keeps it copy-pasteable; the bytes are base64.
type chainJSON struct {
	Chain []delegationJSON `json:"chain"`
}

type delegationJSON struct {
	Content   string `json:"content"`
	Signature string `json:"signature"`
}

// EncodeChain serializes a delegation chain to a portable JSON blob.
func EncodeChain(chain []Delegation) ([]byte, error) {
	cj := chainJSON{Chain: make([]delegationJSON, len(chain))}
	for i, d := range chain {
		cj.Chain[i] = delegationJSON{
			Content:   base64.StdEncoding.EncodeToString(d.Content),
			Signature: base64.StdEncoding.EncodeToString(d.Signature),
		}
	}
	return json.Marshal(cj)
}

// DecodeChain parses a blob produced by EncodeChain.
func DecodeChain(blob []byte) ([]Delegation, error) {
	var cj chainJSON
	if err := json.Unmarshal(blob, &cj); err != nil {
		return nil, fmt.Errorf("wallet: parse chain: %w", err)
	}
	out := make([]Delegation, len(cj.Chain))
	for i, dj := range cj.Chain {
		content, err := base64.StdEncoding.DecodeString(dj.Content)
		if err != nil {
			return nil, fmt.Errorf("wallet: chain[%d].content: %w", i, err)
		}
		sig, err := base64.StdEncoding.DecodeString(dj.Signature)
		if err != nil {
			return nil, fmt.Errorf("wallet: chain[%d].signature: %w", i, err)
		}
		out[i] = Delegation{Content: content, Signature: sig}
	}
	return out, nil
}
