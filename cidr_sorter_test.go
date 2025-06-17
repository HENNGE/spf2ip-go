package spf2ip

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRSorter(t *testing.T) {
	t.Parallel()

	for description, tc := range map[string]struct {
		cidrs    []string
		expected []string
	}{
		"empty": {
			cidrs:    []string{},
			expected: []string{},
		},
		"IPv4": {
			cidrs:    []string{"5.6.7.8/32", "1.1.1.0/24", "1.2.3.4/32"},
			expected: []string{"1.1.1.0/24", "1.2.3.4/32", "5.6.7.8/32"},
		},
		"IPv6": {
			cidrs:    []string{"2001:db8:abcd::/48", "2001:db8::/32", "2001:db8:1234::/64"},
			expected: []string{"2001:db8::/32", "2001:db8:1234::/64", "2001:db8:abcd::/48"},
		},
		"mixed": {
			cidrs:    []string{"2001:db8::/32", "1.1.1.0/24", "4.5.6.7/32", "2001:db8:abcd::/48"},
			expected: []string{"1.1.1.0/24", "4.5.6.7/32", "2001:db8::/32", "2001:db8:abcd::/48"},
		},
		"invalid": {
			cidrs:    []string{"invalid", "", "1.2.3.4/32"},
			expected: []string{"1.2.3.4/32", "", "invalid"},
		},
	} {
		t.Run(description, func(t *testing.T) {
			t.Parallel()

			// Create a copy of the CIDRs to avoid modifying the original slice.
			cidrs := make([]string, len(tc.cidrs))
			copy(cidrs, tc.cidrs)

			sort.Sort(cidrSorter(cidrs))

			assert.Equal(t, tc.expected, cidrs, "Sorted CIDRs should match expected order")
		})
	}
}
