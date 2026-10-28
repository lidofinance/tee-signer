// Command specvectors converts the request examples in Web3Signer's
// openapi-specs/eth2/signing/paths/sign.yaml into the JSON test vectors used by
// web3signer-api/signing and cmd/blsverify. Run scripts/update-spec-vectors.sh.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		panic(err)
	}
	examples := doc["post"].(map[string]any)["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["examples"].(map[string]any)
	out := map[string]any{}
	for name, ex := range examples {
		out[name] = ex.(map[string]any)["value"]
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "%d examples\n", len(out))
}
