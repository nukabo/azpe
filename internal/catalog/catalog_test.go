package catalog_test

import (
	"testing"

	"github.com/nukabo/azpe/internal/catalog"
	"github.com/nukabo/azpe/internal/target"
)

func TestEmbeddedCatalogMatch(t *testing.T) {
	cat, err := catalog.LoadCatalog()
	if err != nil {
		t.Fatalf("failed to load embedded catalog: %v", err)
	}

	if len(cat.RecognizedPatterns) == 0 {
		t.Fatal("embedded catalog recognizedPatterns is empty")
	}

	for _, p := range cat.RecognizedPatterns {
		testHost := "mytest" + p.Suffix
		tgtType, family := target.ClassifyTarget(testHost)
		if tgtType != target.TargetTypeRecognizedAzure {
			t.Errorf("expected RECOGNIZED_AZURE_SERVICE for '%s', got '%s'", testHost, tgtType)
		}
		if string(family) != p.Family {
			t.Errorf("expected family '%s' for '%s', got '%s'", p.Family, testHost, family)
		}
	}

	for _, d := range cat.PossibleDomains {
		testHost := "mytest" + d
		tgtType, _ := target.ClassifyTarget(testHost)
		if tgtType == target.TargetTypeUnrecognized {
			t.Errorf("expected target recognition for possible domain '%s', got UNRECOGNIZED_TARGET", testHost)
		}
	}
}
