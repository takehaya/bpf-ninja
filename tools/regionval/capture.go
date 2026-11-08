package regionval

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Capture is one capture file (README.md, Capture files). Fields regionval does not use are kept
// as raw JSON. Floors are trusted; Hints are untrusted (κ is re-verified).
type Capture struct {
	Format                 int             `json:"format"`
	Kernel                 string          `json:"kernel"`
	Program                string          `json:"program"`
	OriginalInsnsHex       string          `json:"original_insns_hex"`
	OriginalFuncInfoHex    string          `json:"original_func_info_hex"`
	TransformedInsnsHex    string          `json:"transformed_insns_hex"`
	TransformedFuncInfoHex string          `json:"transformed_func_info_hex"`
	TransformedBTFHex      string          `json:"transformed_btf_hex"`
	Floors                 []Floor         `json:"floors"`
	Hints                  Hints           `json:"hints"`
	Checker                json.RawMessage `json:"checker"`
	Mutation               json.RawMessage `json:"mutation,omitempty"`
}

type Floor struct {
	Name  string `json:"name"`
	Floor int16  `json:"floor"`
}

type Hints struct {
	Certificate *struct {
		Original []int `json:"original"`
	} `json:"certificate"`
}

func LoadCapture(path string) (*Capture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Capture
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Format != 1 {
		return nil, fmt.Errorf("%s: format %d, want 1", path, c.Format)
	}
	return &c, nil
}

// blobs decodes the hex fields: original, transformed, original func_info,
// transformed func_info, BTF.
func (c *Capture) blobs() ([5][]byte, error) {
	var out [5][]byte
	for i, s := range []string{c.OriginalInsnsHex, c.TransformedInsnsHex, c.OriginalFuncInfoHex, c.TransformedFuncInfoHex, c.TransformedBTFHex} {
		b, err := hex.DecodeString(s)
		if err != nil {
			return out, fmt.Errorf("hex field %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}
