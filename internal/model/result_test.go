package model_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/target"
	"github.com/azpe/azpe/internal/version"
)

func TestResultJSONSerialization(t *testing.T) {
	tgt, err := target.Parse("myvault.vault.azure.net")
	if err != nil {
		t.Fatalf("failed to parse target: %v", err)
	}

	dnsObs := model.DNSObservation{
		Status:        assess.DNSStatusSuccess,
		QueryHostname: "myvault.vault.azure.net",
		DurationMs:    12,
		Addresses: []model.IPObservation{
			{
				Address:        "10.42.3.7",
				Version:        "IPv4",
				Classification: assess.AddrPrivate,
			},
		},
		AggregateClassification: assess.AggregatePrivateOnly,
	}

	addrObs := model.AddrObservation{
		Classification: assess.AggregatePrivateOnly,
		Addresses:      dnsObs.Addresses,
		PrivateIPs:     []string{"10.42.3.7"},
		PublicIPs:      []string{},
	}

	res := model.NewResultFromDNS(tgt, time.Now(), dnsObs, addrObs)
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to marshal Result: %v", err)
	}

	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if int(unmarshaled["schemaVersion"].(float64)) != version.SchemaVersion {
		t.Errorf("expected schemaVersion %d, got %v", version.SchemaVersion, unmarshaled["schemaVersion"])
	}

	if unmarshaled["toolVersion"] != version.Version {
		t.Errorf("expected toolVersion %s, got %v", version.Version, unmarshaled["toolVersion"])
	}

	dnsMap, ok := unmarshaled["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("dns field is missing or invalid")
	}

	if dnsMap["aggregateClassification"] != "PRIVATE_ONLY" {
		t.Errorf("expected aggregateClassification PRIVATE_ONLY, got %v", dnsMap["aggregateClassification"])
	}
}
