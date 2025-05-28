package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strings"
)

const (
	ipv4 = 4
	ipv6 = 6

	maxSPFIncludeDepth = 10
)

var (
	ErrInvalidIPVersion = errors.New("invalid IP version specified, must be 4 or 6")
	ErrLoopDetected     = errors.New("loop detected in SPF resolution")
	ErrExceededMaxDepth = errors.New("maximum SPF include depth exceeded")
)

type SPF2IPResolver struct {
	ipVersion    int
	netResolver  NetResolver
	debugLogging bool

	// Map of visited domains in the current path for loop detection: domain -> struct{}
	domainsVisitedInCurrentPath map[string]struct{}
	// Map of resolved IPs for each domain: domain -> IPs -> struct{}
	resolvedIPsCache map[string]map[string]struct{}
}

//go:generate mockgen -package main -source spf2ip.go -destination netresolver_mock.go
type NetResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

func NewSPF2IPResolver(netResolver NetResolver, debugLogging bool) *SPF2IPResolver {
	return &SPF2IPResolver{
		netResolver:  netResolver,
		debugLogging: debugLogging,
	}
}

func (r *SPF2IPResolver) Resolve(ctx context.Context, domain string, ipVersion int) ([]string, error) {
	if ipVersion != ipv4 && ipVersion != ipv6 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidIPVersion, ipVersion)
	}

	r.ipVersion = ipVersion
	r.domainsVisitedInCurrentPath = make(map[string]struct{})
	r.resolvedIPsCache = make(map[string]map[string]struct{})

	finalIPs, err := r.processDomain(ctx, domain, 0)
	if err != nil {
		return nil, err
	}

	if finalIPs == nil {
		return []string{}, nil
	}

	result := make([]string, 0, len(finalIPs))
	for ip := range finalIPs {
		result = append(result, ip)
	}

	sort.Sort(cidrSorter{result})

	return result, nil
}

func (r *SPF2IPResolver) processDomain(ctx context.Context, domain string, depth int) (map[string]struct{}, error) {
	if depth > maxSPFIncludeDepth {
		return nil, fmt.Errorf("%w: %s (depth %d)", ErrExceededMaxDepth, domain, depth)
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check if this domain's SPF is already resolved and cached.
	if cachedIPs, found := r.resolvedIPsCache[domain]; found {
		r.debugLogPrintf("Debug: Using cached result for domain: %s", domain)
		return deepCopyMap(cachedIPs), nil
	}

	// Check for loops in the current resolution path.
	if _, visited := r.domainsVisitedInCurrentPath[domain]; visited {
		log.Printf("Warning: Loop detected for domain %s", domain)
		return nil, fmt.Errorf("%w: %s", ErrLoopDetected, domain)
	}

	r.domainsVisitedInCurrentPath[domain] = struct{}{}
	defer delete(r.domainsVisitedInCurrentPath, domain)

	r.debugLogPrintf("Debug: Processing domain: %s (depth %d)", domain, depth)

	currentDomainIPs := make(map[string]struct{})

	spfString, err := r.getSPFRecord(ctx, domain)
	if err != nil {
		if !errors.Is(err, errIgnorableDNSErr) {
			log.Printf("Warning: Failed to get SPF record for %s: %v", domain, err)
			r.resolvedIPsCache[domain] = nil

			return nil, err
		}
	}

	if spfString == "" {
		log.Printf("No SPF record found for %s, treating as empty", domain)
		r.resolvedIPsCache[domain] = currentDomainIPs

		return currentDomainIPs, nil
	}

	// Regular expression to match SPF mechanisms/modifiers.
	reMechanism := regexp.MustCompile(`^([+~-]?)(ip4|ip6|a|mx|include|redirect|exists|ptr|all)((?::|=)(.+))?$`)

	for _, term := range strings.Fields(spfString)[1:] { // Skip "v=spf1"
		term = strings.ToLower(term)
		r.debugLogPrintf("Debug: Processing term: %s", term)

		matches := reMechanism.FindStringSubmatch(term)
		if matches == nil {
			r.debugLogPrintf("Debug: Skipping unrecognized term: %s", term)
			continue
		}

		mechanism := matches[2] // Mechanism/Modifier type (ip4, ip6, a, mx, include, redirect, exists, ptr, all).
		value := ""             // Value for the mechanism/modifier (if applicable).

		if len(matches) > 4 {
			value = matches[4]
		}

		switch mechanism {
		case "ip4":
			if r.ipVersion == ipv4 {
				if err := r.addIPOrCIDRToSet(value, currentDomainIPs); err != nil {
					return nil, fmt.Errorf("failed to add IP/CIDR for ip4 mechanism in %s: %w", domain, err)
				}
			}

		case "ip6":
			if r.ipVersion == ipv6 {
				if err := r.addIPOrCIDRToSet(value, currentDomainIPs); err != nil {
					return nil, fmt.Errorf("failed to add IP/CIDR for ip6 mechanism in %s: %w", domain, err)
				}
			}

		case "a":
			targetHost, maskSuffix := parseSPFMechanismTargetAndMask(domain, value)

			ips, err := r.netResolver.LookupIP(ctx, r.lookupIPNetwork(), targetHost)
			if err != nil {
				if isDNSErrIgnorable(err) {
					r.debugLogPrintf("Debug: Ignorable DNS error for A/AAAA lookup of %s (directive in %s): %v", targetHost, domain, err)
					continue
				}

				return nil, fmt.Errorf("A/AAAA lookup failed for %s (directive in %s): %w", targetHost, domain, err)
			}

			for _, ip := range ips {
				if err := r.addIPOrCIDRToSet(ip.String()+maskSuffix, currentDomainIPs); err != nil {
					return nil, fmt.Errorf("failed to add IP/CIDR for A mechanism in %s: %w", domain, err)
				}
			}

		case "mx":
			targetHost, maskSuffix := parseSPFMechanismTargetAndMask(domain, value)

			mxs, err := r.netResolver.LookupMX(ctx, targetHost)
			if err != nil {
				if isDNSErrIgnorable(err) {
					r.debugLogPrintf("Debug: Ignorable DNS error for MX lookup of %s (directive in %s): %v", targetHost, domain, err)
					continue
				}

				return nil, fmt.Errorf("MX lookup failed for %s (directive in %s): %w", targetHost, domain, err)
			}

			for _, mx := range mxs {
				mxHost := strings.TrimSuffix(mx.Host, ".")

				ips, err := r.netResolver.LookupIP(ctx, r.lookupIPNetwork(), mxHost)
				if err != nil {
					if !isDNSErrIgnorable(err) {
						return nil, fmt.Errorf("A/AAAA lookup failed for MX host %s (directive in %s): %w", mxHost, domain, err)
					}

					r.debugLogPrintf("Debug: Ignorable DNS error for MX host %s (directive in %s): %v", mxHost, domain, err)

					continue // Skip this MX host if DNS error is ignorable
				}

				for _, ip := range ips {
					if err := r.addIPOrCIDRToSet(ip.String()+maskSuffix, currentDomainIPs); err != nil {
						return nil, fmt.Errorf("failed to add IP/CIDR for MX mechanism in %s: %w", domain, err)
					}
				}
			}

		case "include":
			if value != "" {
				includedIPs, includeErr := r.processDomain(ctx, value, depth+1)
				if includeErr != nil {
					return nil, fmt.Errorf("include failed for %s (directive in %s): %w", value, domain, includeErr)
				} else {
					for ip := range includedIPs {
						currentDomainIPs[ip] = struct{}{}
					}
				}
			} else {
				log.Printf("Warning: 'include' modifier without domain in %s", domain)
				r.resolvedIPsCache[domain] = nil

				return nil, fmt.Errorf("include without domain in %s", domain)
			}

		case "redirect":
			if value != "" {
				r.debugLogPrintf("Debug: Redirecting from %s to %s. Discarding IPs found so far for %s.", domain, value, domain)

				// The result of this domain's processing is now entirely determined by the redirect target.
				redirectedIPs, redirectErr := r.processDomain(ctx, value, depth+1)
				r.resolvedIPsCache[domain] = deepCopyMap(redirectedIPs) // Overwrite cache with redirected IPs

				return redirectedIPs, redirectErr
			}

			log.Printf("Warning: 'redirect' modifier without domain in %s", domain)
			r.resolvedIPsCache[domain] = nil

			return nil, fmt.Errorf("redirect without domain in %s", domain)

		case "exists", "ptr", "all":
			// These mechanisms don't directly define IPs in the same way, ignore for IP extraction.
			r.debugLogPrintf("Debug: Skipping mechanism not used for IP extraction: %s", mechanism)

		default:
			r.debugLogPrintf("Debug: Skipping unknown mechanism: %s", mechanism)
		}
	}

	r.resolvedIPsCache[domain] = deepCopyMap(currentDomainIPs)

	return currentDomainIPs, nil
}

func (r *SPF2IPResolver) lookupIPNetwork() string {
	switch r.ipVersion {
	case ipv4:
		return "ip4"
	case ipv6:
		return "ip6"
	default:
		return "ip" // Fallback, should not happen if ipVersion is correctly set
	}
}

func parseSPFMechanismTargetAndMask(defaultDomain, mechanismValue string) (targetHost, maskSuffix string) {
	targetHost = defaultDomain
	maskSuffix = ""

	trimmedValue := strings.TrimSpace(mechanismValue)
	if trimmedValue != "" {
		parts := strings.SplitN(trimmedValue, "/", 2) // Example: "example.com/24" -> ["example.com", "24"]

		if hostPart := strings.TrimSpace(parts[0]); hostPart != "" {
			targetHost = hostPart
		} // If hostPart is empty, targetHost remains defaultDomain

		if len(parts) == 2 {
			maskPart := strings.TrimSpace(parts[1])
			if maskPart != "" {
				maskSuffix = "/" + maskPart
			}
		}
	}

	return targetHost, maskSuffix
}

var (
	errIgnorableDNSErr = errors.New("ignorable DNS error")
	errDNSErr          = errors.New("DNS error")
)

func (r *SPF2IPResolver) getSPFRecord(ctx context.Context, domain string) (string, error) {
	txtRecords, err := r.netResolver.LookupTXT(ctx, domain)
	if err != nil {
		if isDNSErrIgnorable(err) {
			r.debugLogPrintf("Debug: Ignorable DNS error for TXT lookup of %s: %v", domain, err)
			return "", fmt.Errorf("%w: %s", errIgnorableDNSErr, err)
		}

		return "", fmt.Errorf("%w: %s", errDNSErr, err)
	}

	for _, record := range txtRecords {
		trimmedRecord := strings.TrimSpace(record)

		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1 ") {
			return trimmedRecord, nil
		}
	}

	log.Printf("No record starting with 'v=spf1 ' found for %s", domain)

	return "", nil // No SPF record found
}

// addIPOrCIDRToSet adds an IP or CIDR block to the target set, ensuring that plain IPs are converted to CIDR notation.
func (r *SPF2IPResolver) addIPOrCIDRToSet(value string, targetSet map[string]struct{}) error {
	value = strings.TrimSpace(value)

	// Try CIDR first
	if ip, ipNet, err := net.ParseCIDR(value); err == nil {
		if (r.ipVersion == ipv4 && ip.To4() != nil) || (r.ipVersion == ipv6 && ip.To4() == nil && ip.To16() != nil) {
			targetSet[ipNet.String()] = struct{}{}
			return nil
		}

		return fmt.Errorf("CIDR '%s' is not of the required IP version (v%d)", value, r.ipVersion)
	}

	// Try plain IP
	ip := net.ParseIP(value)
	if ip != nil {
		if r.ipVersion == ipv4 && ip.To4() != nil {
			// Convert IPv4 to CIDR notation
			targetSet[ip.To4().String()+"/32"] = struct{}{}
			return nil
		}

		if r.ipVersion == ipv6 && ip.To4() == nil && ip.To16() != nil {
			// Convert IPv6 to CIDR notation
			targetSet[ip.String()+"/128"] = struct{}{}
			return nil
		}

		return fmt.Errorf("IP address '%s' is not of the required IP version (v%d)", value, r.ipVersion)
	}

	return fmt.Errorf("value '%s' is not a valid IP address or CIDR block", value)
}

func (r *SPF2IPResolver) debugLogPrintf(format string, args ...interface{}) {
	if r.debugLogging {
		log.Printf(format, args...)
	}
}

// isDNSErrIgnorable identifies DNS errors where a record is definitively not found (e.g., NXDOMAIN).
// In SPF, this means no SPF record exists (an SPF "None" result),
// distinct from temporary or permanent operational DNS errors.
func isDNSErrIgnorable(err error) bool {
	if err == nil {
		return false
	}

	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}

	return false
}
