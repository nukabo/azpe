package catalog

import (
	_ "embed"
	"encoding/json"
)

//go:embed azure-services.json
var CatalogJSON []byte

type Pattern struct {
	Suffix string `json:"suffix"`
	Family string `json:"family"`
}

type CatalogData struct {
	RecognizedPatterns []Pattern `json:"recognizedPatterns"`
	PossibleDomains    []string  `json:"possibleDomains"`
}

// LoadCatalog unmarshals the embedded azure-services.json.
func LoadCatalog() (*CatalogData, error) {
	var c CatalogData
	if err := json.Unmarshal(CatalogJSON, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
