package spf2ip

import (
	"bytes"
	"net"
)

type cidrSorter []string

func (s cidrSorter) Len() int      { return len(s) }
func (s cidrSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s cidrSorter) Less(i, j int) bool {
	ip1, p1, isV4_1 := parseCIDR(s[i])
	ip2, p2, isV4_2 := parseCIDR(s[j])

	isValid1 := ip1 != nil
	isValid2 := ip2 != nil

	if !isValid1 && !isValid2 {
		return s[i] < s[j]
	} // Both invalid, sort by string

	if !isValid1 {
		return false
	} // Invalid sorts after valid

	if !isValid2 {
		return true
	} // Valid sorts before invalid

	// Both are valid CIDRs
	if isV4_1 != isV4_2 {
		return isV4_1 // IPv4 comes before IPv6
	}

	if cmp := bytes.Compare(ip1, ip2); cmp != 0 {
		return cmp < 0
	}

	return p1 < p2 // Smaller prefix (wider network) comes first
}

// parseCIDR parses a CIDR notation string and returns the IP, prefix length, and whether it's IPv4.
func parseCIDR(s string) (ip net.IP, prefix int, isV4 bool) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, 0, false
	}

	ip = ipNet.IP
	prefix, _ = ipNet.Mask.Size()

	if ip4 := ip.To4(); ip4 != nil {
		return ip4, prefix, true
	}

	return ip, prefix, false
}
