package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/azpe/azpe/internal/assess"
	"github.com/azpe/azpe/internal/model"
	"github.com/azpe/azpe/internal/target"
)

// Resolver interface abstracts DNS resolution for testability.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// OSResolver uses the operating-system's standard net.DefaultResolver.
type OSResolver struct{}

// LookupNetIP performs host DNS lookup using the OS resolver.
func (r *OSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// Resolve executes DNS resolution and IP classification for a target.
func Resolve(ctx context.Context, resolver Resolver, tgt *target.Target) (model.DNSObservation, model.AddrObservation) {
	startTime := time.Now()

	// Check if target hostname is an IP literal
	if ipAddr, err := netip.ParseAddr(tgt.Hostname); err == nil {
		duration := time.Since(startTime).Milliseconds()
		version := "IPv4"
		if ipAddr.Is6() {
			version = "IPv6"
		}
		class := assess.ClassifyIP(ipAddr)
		obs := model.IPObservation{
			Address:        ipAddr.String(),
			Version:        version,
			Classification: class,
		}
		aggClass := assess.CalculateAggregateClassification([]assess.AddressClassification{class})

		dnsObs := model.DNSObservation{
			Status:                  assess.DNSStatusNotApplicable,
			QueryHostname:           tgt.Hostname,
			DurationMs:              duration,
			Addresses:               []model.IPObservation{obs},
			AggregateClassification: aggClass,
			IsIPLiteral:             true,
			Note:                    "Target is an IP literal. No hostname DNS resolution occurred.",
		}

		addrObs := buildAddrObservation(dnsObs.Addresses, aggClass)
		return dnsObs, addrObs
	}

	if resolver == nil {
		resolver = &OSResolver{}
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip", tgt.Hostname)
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		status, errCat := categorizeDNSError(ctx, err)
		dnsObs := model.DNSObservation{
			Status:                  status,
			QueryHostname:           tgt.Hostname,
			DurationMs:              duration,
			Addresses:               []model.IPObservation{},
			AggregateClassification: assess.AggregateNone,
			ErrorCategory:           errCat,
			ErrorMessage:            err.Error(),
			Note:                    "DNS resolution failed",
		}
		addrObs := model.AddrObservation{
			Classification: assess.AggregateNone,
			Addresses:      []model.IPObservation{},
			PrivateIPs:     []string{},
			PublicIPs:      []string{},
			Note:           "No IP addresses resolved",
		}
		return dnsObs, addrObs
	}

	deduped := deduplicateAndSort(addrs)
	var ipObsList []model.IPObservation
	var classes []assess.AddressClassification

	for _, addr := range deduped {
		ver := "IPv4"
		if addr.Is6() {
			ver = "IPv6"
		}
		cls := assess.ClassifyIP(addr)
		classes = append(classes, cls)
		ipObsList = append(ipObsList, model.IPObservation{
			Address:        addr.String(),
			Version:        ver,
			Classification: cls,
		})
	}

	aggClass := assess.CalculateAggregateClassification(classes)

	dnsObs := model.DNSObservation{
		Status:                  assess.DNSStatusSuccess,
		QueryHostname:           tgt.Hostname,
		DurationMs:              duration,
		Addresses:               ipObsList,
		AggregateClassification: aggClass,
	}

	addrObs := buildAddrObservation(ipObsList, aggClass)
	return dnsObs, addrObs
}

func buildAddrObservation(ipObsList []model.IPObservation, aggClass assess.AggregateClassification) model.AddrObservation {
	var privateIPs []string
	var publicIPs []string

	for _, ipObs := range ipObsList {
		if ipObs.Classification == assess.AddrPrivate {
			privateIPs = append(privateIPs, ipObs.Address)
		} else if ipObs.Classification == assess.AddrPublic {
			publicIPs = append(publicIPs, ipObs.Address)
		}
	}

	return model.AddrObservation{
		Classification: aggClass,
		Addresses:      ipObsList,
		PrivateIPs:     privateIPs,
		PublicIPs:      publicIPs,
	}
}

func deduplicateAndSort(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var unique []netip.Addr
	for _, a := range addrs {
		// Normalize IPv4-mapped IPv6 if needed, but preserve standard netip behavior
		unmapped := a.Unmap()
		if !seen[unmapped] {
			seen[unmapped] = true
			unique = append(unique, unmapped)
		}
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Compare(unique[j]) < 0
	})

	return unique
}

func categorizeDNSError(ctx context.Context, err error) (assess.DNSStatus, string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
		return assess.DNSStatusTimeout, "TIMEOUT"
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return assess.DNSStatusTimeout, "TIMEOUT"
		}
		if dnsErr.IsNotFound {
			return assess.DNSStatusNotFound, "NOT_FOUND"
		}
		if dnsErr.IsTemporary {
			return assess.DNSStatusTemporaryFailure, "TEMPORARY_FAILURE"
		}
	}

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "not found") {
		return assess.DNSStatusNotFound, "NOT_FOUND"
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return assess.DNSStatusTimeout, "TIMEOUT"
	}
	if strings.Contains(errStr, "temporary") || strings.Contains(errStr, "server failure") || strings.Contains(errStr, "servfail") {
		return assess.DNSStatusTemporaryFailure, "TEMPORARY_FAILURE"
	}

	return assess.DNSStatusFailure, "GENERIC_ERROR"
}
