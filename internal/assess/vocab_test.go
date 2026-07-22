package assess_test

import (
	"testing"

	"github.com/azpe/azpe/internal/assess"
)

func TestVocab(t *testing.T) {
	if assess.AssessmentWorking.String() != "WORKING" {
		t.Errorf("expected WORKING, got %s", assess.AssessmentWorking.String())
	}
	if assess.AssessmentNotPrivate.String() != "NOT_PRIVATE" {
		t.Errorf("expected NOT_PRIVATE, got %s", assess.AssessmentNotPrivate.String())
	}
	if assess.AssessmentBroken.String() != "BROKEN" {
		t.Errorf("expected BROKEN, got %s", assess.AssessmentBroken.String())
	}
	if assess.AssessmentUnknown.String() != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %s", assess.AssessmentUnknown.String())
	}

	if assess.OwnerDNSOrNetwork.String() != "DNS_OR_NETWORK" {
		t.Errorf("expected DNS_OR_NETWORK, got %s", assess.OwnerDNSOrNetwork.String())
	}
	if assess.OwnerNetwork.String() != "NETWORK" {
		t.Errorf("expected NETWORK, got %s", assess.OwnerNetwork.String())
	}
	if assess.OwnerApplicationOrIdentity.String() != "APPLICATION_OR_IDENTITY" {
		t.Errorf("expected APPLICATION_OR_IDENTITY, got %s", assess.OwnerApplicationOrIdentity.String())
	}
	if assess.OwnerSecurityOrProxy.String() != "SECURITY_OR_PROXY" {
		t.Errorf("expected SECURITY_OR_PROXY, got %s", assess.OwnerSecurityOrProxy.String())
	}
	if assess.OwnerUnknown.String() != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %s", assess.OwnerUnknown.String())
	}
}
