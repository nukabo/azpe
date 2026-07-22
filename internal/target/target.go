package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Target represents a normalized connectivity probe target.
type Target struct {
	OriginalInput      string             `json:"originalInput"`
	Scheme             string             `json:"scheme"`
	Hostname           string             `json:"hostname"`
	Port               int                `json:"port"`
	RequestPath        string             `json:"requestPath"`
	TargetType         TargetType         `json:"targetType"`
	AzureServiceFamily AzureServiceFamily `json:"azureServiceFamily,omitempty"`
}

// Parse takes a raw input string and normalizes it into a Target model.
// Returns an error if the input is missing, malformed, or unsafe.
func Parse(rawInput string) (*Target, error) {
	trimmed := strings.TrimSpace(rawInput)
	if trimmed == "" {
		return nil, fmt.Errorf("missing target")
	}

	// Reject control characters or invalid whitespace inside input
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return nil, fmt.Errorf("target contains invalid control characters")
		}
	}

	rawToParse := trimmed
	hasScheme := strings.Contains(trimmed, "://")

	if hasScheme {
		schemeEnd := strings.Index(trimmed, "://")
		scheme := strings.ToLower(trimmed[:schemeEnd])
		if scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("unsupported scheme %q (only http and https are supported)", scheme)
		}
	} else {
		// Default to https scheme if none provided
		rawToParse = "https://" + trimmed
	}

	u, err := url.Parse(rawToParse)
	if err != nil {
		return nil, fmt.Errorf("malformed target URL: %w", err)
	}

	if u.User != nil {
		return nil, fmt.Errorf("URLs containing embedded credentials are not allowed")
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}

	hostStr := u.Host
	if hostStr == "" {
		return nil, fmt.Errorf("missing hostname in target")
	}

	hostname := hostStr
	port := 0

	if strings.Contains(hostStr, ":") {
		h, pStr, err := net.SplitHostPort(hostStr)
		if err != nil {
			// Could be a bracketed or unbracketed IPv6 address without port
			if (strings.Count(hostStr, ":") > 1 && !strings.HasPrefix(hostStr, "[")) || (strings.HasPrefix(hostStr, "[") && strings.HasSuffix(hostStr, "]")) {
				hostname = hostStr
			} else {
				return nil, fmt.Errorf("invalid host:port format %q: %w", hostStr, err)
			}
		} else {
			hostname = h
			parsedPort, err := strconv.Atoi(pStr)
			if err != nil || parsedPort < 1 || parsedPort > 65535 {
				return nil, fmt.Errorf("invalid port number %q (must be 1-65535)", pStr)
			}
			port = parsedPort
		}
	}

	// Trim brackets from IPv6 hostnames if present for Hostname
	cleanHostname := strings.TrimPrefix(strings.TrimSuffix(hostname, "]"), "[")
	if cleanHostname == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	if err := validateHostnameOrIP(cleanHostname); err != nil {
		return nil, fmt.Errorf("invalid target hostname %q: %w", cleanHostname, err)
	}

	if port == 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}

	requestPath := u.Path
	if u.RawQuery != "" {
		requestPath += "?" + u.RawQuery
	}
	if requestPath == "" {
		requestPath = "/"
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}

	targetType, family := ClassifyTarget(cleanHostname)

	return &Target{
		OriginalInput:      trimmed,
		Scheme:             scheme,
		Hostname:           cleanHostname,
		Port:               port,
		RequestPath:        requestPath,
		TargetType:         targetType,
		AzureServiceFamily: family,
	}, nil
}

// RedactQueryValues redacts query parameter values in request URIs or Location headers.
func RedactQueryValues(path string) string {
	idx := strings.Index(path, "?")
	if idx == -1 {
		return path
	}

	basePath := path[:idx]
	queryStr := path[idx+1:]
	if queryStr == "" {
		return path
	}

	// Preserve hash fragment separation if any
	fragment := ""
	if fragIdx := strings.Index(queryStr, "#"); fragIdx != -1 {
		fragment = queryStr[fragIdx:]
		queryStr = queryStr[:fragIdx]
	}

	pairs := strings.Split(queryStr, "&")
	var redactedPairs []string
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		eqIdx := strings.Index(pair, "=")
		if eqIdx != -1 {
			key := pair[:eqIdx]
			redactedPairs = append(redactedPairs, key+"=REDACTED")
		} else {
			redactedPairs = append(redactedPairs, pair)
		}
	}

	return basePath + "?" + strings.Join(redactedPairs, "&") + fragment
}

// SanitizeLocation strips user credentials (userinfo) and redacts query parameter values from Location headers.
func SanitizeLocation(locStr string) string {
	if locStr == "" {
		return ""
	}
	u, err := url.Parse(locStr)
	if err != nil {
		return RedactQueryValues(locStr)
	}
	u.User = nil // Strip userinfo (e.g. user:password@)
	return RedactQueryValues(u.String())
}

func validateHostnameOrIP(host string) error {
	// Check if valid IP address (v4 or v6)
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}

	// Validate as DNS hostname (RFC 1123 / RFC 952)
	if len(host) > 253 {
		return fmt.Errorf("hostname exceeds maximum length of 253 characters")
	}

	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("empty label in hostname")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label %q cannot start or end with hyphen", label)
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return fmt.Errorf("invalid character %q in label %q", r, label)
			}
		}
	}

	return nil
}
