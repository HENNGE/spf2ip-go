package spf2ip

import (
	"context"
	"fmt"
	net "net"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type SPF2IPTestSuite struct {
	gomock         *gomock.Controller
	netResolver    *MockNetResolver
	spf2IPResolver *SPF2IPResolver
}

func NewSPF2IPTestSuite(t *testing.T) *SPF2IPTestSuite {
	gomockController := gomock.NewController(t)
	netResolver := NewMockNetResolver(gomockController)
	spf2IPResolver := NewSPF2IPResolver(netResolver, true)

	return &SPF2IPTestSuite{
		gomock:         gomockController,
		netResolver:    netResolver,
		spf2IPResolver: spf2IPResolver,
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
		[]string{"v=spf1 ip4:1.2.3.0/28 include:first.included.com include:second.included.com a mx:mx.example.com -all"}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "first.included.com").Return(
		[]string{"v=spf1 ip4:5.6.7.8 ip6:2001:db8::1 include:nxdomain.included.com -all"}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "second.included.com").Return(
		[]string{"v=spf1 include:first.included.com ip4:1.0.0.0/24 -all"}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupMX(gomock.Any(), "mx.example.com").Return(
		[]*net.MX{
			{Host: "mail1.example.com", Pref: 10},
			{Host: "mail2.example.com", Pref: 20},
		}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "mail1.example.com").Return(
		[]net.IP{net.ParseIP("2.3.4.5")}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "mail2.example.com").Return(
		[]net.IP{net.ParseIP("3.4.5.6")}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "example.com").Return(
		[]net.IP{net.ParseIP("8.8.8.8")}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "nxdomain.included.com").Return(
		nil, &net.DNSError{IsNotFound: true}, // Simulating an ignorable DNS error
	).Times(1)

	expectedIPs := []string{"1.0.0.0/24", "1.2.3.0/28", "2.3.4.5/32", "3.4.5.6/32", "5.6.7.8/32", "8.8.8.8/32"}

	actualIPs, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
	assert.NoError(t, err)
	assert.Equal(t, expectedIPs, actualIPs)
}

func TestResolve_IPVersions(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	lookupTXTMockCall := func() {
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 ip4:5.6.7.8 ip6:2001:db8::1 ip4:1.2.3.4 -all"}, nil,
		).Times(1)
	}

	for description, tc := range map[string]struct {
		ipVersion   int
		expectedIPs []string
		expectedErr error
	}{
		"IPv4 resolution": {
			ipVersion:   ipv4,
			expectedIPs: []string{"1.2.3.4/32", "5.6.7.8/32"},
			expectedErr: nil,
		},
		"IPv6 resolution": {
			ipVersion:   ipv6,
			expectedIPs: []string{"2001:db8::1/128"},
			expectedErr: nil,
		},
		"Invalid IP version": {
			ipVersion:   5,
			expectedIPs: nil,
			expectedErr: ErrInvalidIPVersion,
		},
	} {
		t.Run(description, func(t *testing.T) {
			if tc.expectedErr == nil {
				lookupTXTMockCall()
			}

			actualIPs, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", tc.ipVersion)
			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedIPs, actualIPs)
		})
	}
}

func TestResolve_AMechanism(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	{
		// A mechanism with value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 a:test.com -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "test.com").Return(
			[]net.IP{net.ParseIP("1.2.3.4")}, nil,
		).Times(1)

		expected := []string{"1.2.3.4/32"}

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}

	{
		// A mechanism without value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 a -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "example.com").Return(
			[]net.IP{net.ParseIP("1.2.3.4")}, nil,
		).Times(1)

		expected := []string{"1.2.3.4/32"}

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestResolve_MXMechanism(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	{
		// MX mechanism with value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 mx:test.com -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupMX(gomock.Any(), "test.com").Return(
			[]*net.MX{
				{Host: "mail1.test.com", Pref: 10},
				{Host: "mail2.test.com", Pref: 20},
			}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "mail1.test.com").Return(
			[]net.IP{net.ParseIP("1.2.3.4")}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "mail2.test.com").Return(
			[]net.IP{net.ParseIP("5.6.7.8")}, nil,
		).Times(1)

		expected := []string{"1.2.3.4/32", "5.6.7.8/32"}

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}

	{
		// MX mechanism without value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 mx -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupMX(gomock.Any(), "example.com").Return(
			[]*net.MX{
				{Host: "mail1.example.com", Pref: 10},
				{Host: "mail2.example.com", Pref: 20},
			}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "mail1.example.com").Return(
			[]net.IP{net.ParseIP("1.2.3.4")}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupIP(gomock.Any(), "ip4", "mail2.example.com").Return(
			[]net.IP{net.ParseIP("5.6.7.8")}, nil,
		).Times(1)

		expected := []string{"1.2.3.4/32", "5.6.7.8/32"}

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestResolve_IncludeMechanism(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	{
		// Normal: Include mechanism with value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 include:included.com -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "included.com").Return(
			[]string{"v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 -all"}, nil,
		).Times(1)

		expected := []string{"1.2.3.4/32"}

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}

	{
		// Error: Include mechanism without value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 include -all"}, nil,
		).Times(1)

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.Error(t, err)
		assert.Empty(t, actual)
	}
}

func TestResolve_RedirectModifier(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	{
		// Normal: Redirect modifier with value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 include:included1.com redirect:redirected.com -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "included1.com").Return(
			[]string{"v=spf1 ip4:9.9.9.9 ip4:10.10.10.10 -all"}, nil,
		).Times(1)
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "redirected.com").Return(
			[]string{"v=spf1 ip4:1.2.3.0/28 -all"}, nil,
		).Times(1)

		expcted := []string{"1.2.3.0/28"}

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.NoError(t, err)
		assert.Equal(t, expcted, actual)
	}

	{
		// Error: Redirect modifier without value
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
			[]string{"v=spf1 redirect -all"}, nil,
		).Times(1)

		actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
		assert.Error(t, err)
		assert.Empty(t, actual)
	}
}

func TestResolve_LoopDetectionErr(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
		[]string{"v=spf1 include:included.com -all"}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "included.com").Return(
		[]string{"v=spf1 include:loop.com -all"}, nil,
	).Times(1)
	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "loop.com").Return(
		[]string{"v=spf1 include:included.com -all"}, nil,
	).Times(1)

	actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
	assert.ErrorIs(t, err, ErrLoopDetected)
	assert.Nil(t, actual)
}

func TestResolve_ExceededMaxDepthErr(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
		[]string{"v=spf1 include:included0.com -all"}, nil,
	).Times(1)

	for i := range maxSPFIncludeDepth { // excluding the first include
		s.netResolver.EXPECT().LookupTXT(gomock.Any(), fmt.Sprintf("included%d.com", i)).Return(
			[]string{fmt.Sprintf("v=spf1 include:included%d.com -all", i+1)}, nil,
		).Times(1)
	}

	actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", ipv4)
	assert.ErrorIs(t, err, ErrExceededMaxDepth)
	assert.Nil(t, actual)
}

func TestResolve_InvalidSPFIPOrCIDR(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	for description, tc := range map[string]struct {
		ipVersion int
		spfRecord string
	}{
		"Invalid IPv4 value": {
			ipVersion: ipv4,
			spfRecord: "v=spf1 ip4:123123123.2 ip4:invalid_ip -all",
		},
		"Invalid IPv6 value": {
			ipVersion: ipv6,
			spfRecord: "v=spf1 ip6:2001111:22222 ip6:invalid_ip -all",
		},
	} {
		t.Run(description, func(t *testing.T) {
			s.netResolver.EXPECT().LookupTXT(gomock.Any(), "example.com").Return(
				[]string{tc.spfRecord}, nil,
			).Times(1)

			actual, err := s.spf2IPResolver.Resolve(context.Background(), "example.com", tc.ipVersion)
			assert.Error(t, err)
			assert.Nil(t, actual)
		})
	}
}

func TestParseSPFMechanismTargetAndMask(t *testing.T) {
	t.Parallel()

	defaultDomain := "default.example.com"

	for description, tc := range map[string]struct {
		mechanismValue     string
		expectedTargetHost string
		expectedMaskSuffix string
	}{
		"With mask": {
			mechanismValue:     "example.com/24",
			expectedTargetHost: "example.com",
			expectedMaskSuffix: "/24",
		},
		"Without mask": {
			mechanismValue:     "example.com",
			expectedTargetHost: "example.com",
			expectedMaskSuffix: "",
		},
		"Empty mechanism value (fallback to default domain)": {
			mechanismValue:     "",
			expectedTargetHost: defaultDomain,
			expectedMaskSuffix: "",
		},
	} {
		t.Run(description, func(t *testing.T) {
			actualTargetHost, actualMaskSuffix := parseSPFMechanismTargetAndMask(defaultDomain, tc.mechanismValue)
			assert.Equal(t, tc.expectedTargetHost, actualTargetHost)
			assert.Equal(t, tc.expectedMaskSuffix, actualMaskSuffix)
		})
	}
}

func TestGetSPFRecord(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	for description, tc := range map[string]struct {
		domain            string
		expectedSPFRecord string
		mockCalls         []any
		expectedErr       error
	}{
		"Valid lookup": {
			domain:            "valid.example.com",
			expectedSPFRecord: "v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 -all",
			mockCalls: []any{
				s.netResolver.EXPECT().LookupTXT(gomock.Any(), "valid.example.com").Return(
					[]string{
						"blah blah blah",
						"  v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 -all ", // With leading/trailing spaces
						"hoge hoge hoge",
					}, nil,
				).Times(1),
			},
			expectedErr: nil,
		},
		"Valid lookup but no SPF record": {
			domain:            "nospf.example.com",
			expectedSPFRecord: "",
			mockCalls: []any{
				s.netResolver.EXPECT().LookupTXT(gomock.Any(), "nospf.example.com").Return(
					[]string{
						"blah blah blah",
						"hoge hoge hoge",
					}, nil,
				).Times(1),
			},
			expectedErr: nil,
		},
		"Failed lookup: Ignorable DNS error": {
			domain:            "ignorable.dns.err.example.com",
			expectedSPFRecord: "",
			mockCalls: []any{
				s.netResolver.EXPECT().LookupTXT(gomock.Any(), "ignorable.dns.err.example.com").Return(
					nil, &net.DNSError{IsNotFound: true},
				).Times(1),
			},
			expectedErr: errIgnorableDNSErr,
		},
		"Failed lookup: DNS error": {
			domain:            "dns.err.example.com",
			expectedSPFRecord: "",
			mockCalls: []any{
				s.netResolver.EXPECT().LookupTXT(gomock.Any(), "dns.err.example.com").Return(
					nil, &net.DNSError{IsNotFound: false},
				).Times(1),
			},
			expectedErr: errDNSErr,
		},
	} {
		t.Run(description, func(t *testing.T) {
			gomock.InOrder(tc.mockCalls...)

			actualSPFRecord, err := s.spf2IPResolver.getSPFRecord(context.Background(), tc.domain)
			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedSPFRecord, actualSPFRecord)
		})
	}
}

func TestAddIPOrCIDRToSet(t *testing.T) {
	t.Parallel()

	s := NewSPF2IPTestSuite(t)

	for description, tc := range map[string]struct {
		ipVersion  int
		value      string
		expectErr  bool
		expectedIP string
	}{
		"Valid IPv4": {
			ipVersion:  ipv4,
			value:      "1.2.3.4",
			expectErr:  false,
			expectedIP: "1.2.3.4/32",
		},
		"Valid IPv4-mapped IPv6 (IPv4 mode)": {
			ipVersion:  ipv4,
			value:      "::ffff:1.2.3.4",
			expectErr:  false,
			expectedIP: "1.2.3.4/32",
		},
		"Valid IPv6": {
			ipVersion:  ipv6,
			value:      "2001:db8::1",
			expectErr:  false,
			expectedIP: "2001:db8::1/128",
		},
		"Valid IPv4 CIDR": {
			ipVersion:  ipv4,
			value:      "1.2.3.0/24",
			expectErr:  false,
			expectedIP: "1.2.3.0/24",
		},
		"Valid IPv4-mapped IPv6 CIDR (IPv4 mode)": {
			ipVersion:  ipv4,
			value:      "::ffff:1.2.3.0/120",
			expectErr:  false,
			expectedIP: "1.2.3.0/24",
		},
		"Valid IPv6 CIDR": {
			ipVersion:  ipv6,
			value:      "2001:db8::/64",
			expectErr:  false,
			expectedIP: "2001:db8::/64",
		},
		"Invalid IPv4": {
			ipVersion:  ipv4,
			value:      "999.999.999.999",
			expectErr:  true,
			expectedIP: "",
		},
		"Invalid IPv6": {
			ipVersion:  ipv6,
			value:      "2001:db8::g",
			expectErr:  true,
			expectedIP: "",
		},
		"Invalid IPv4-mapped IPv6 (IPv4 mode)": {
			ipVersion:  ipv4,
			value:      "::ffff:1.2.3.999",
			expectErr:  true,
			expectedIP: "",
		},
		"Valid IPv4-mapped IPv6 (but IPv6 mode)": {
			ipVersion:  ipv6,
			value:      "::ffff:1.2.3.4",
			expectErr:  true,
			expectedIP: "",
		},
		"Invalid IPv4 CIDR": {
			ipVersion:  ipv4,
			value:      "1.2.3.4/33",
			expectErr:  true,
			expectedIP: "",
		},
		"Invalid IPv4-mapped IPv6 CIDR": {
			ipVersion:  ipv4,
			value:      "::ffff:1.2.3.4/129",
			expectErr:  true,
			expectedIP: "",
		},
		"Valid IPv4-mapped IPv6 CIDR (but IPv6 mode)": {
			ipVersion:  ipv6,
			value:      "::ffff:1.2.3.0/120",
			expectErr:  true,
			expectedIP: "",
		},
		"Invalid IPv6 CIDR": {
			ipVersion:  ipv6,
			value:      "2001:db8::/129",
			expectErr:  true,
			expectedIP: "",
		},
		"Valid IPv4 but wrong version": {
			ipVersion:  ipv6,
			value:      "1.2.3.4",
			expectErr:  true,
			expectedIP: "",
		},
		"Valid IPv6 but wrong version": {
			ipVersion:  ipv4,
			value:      "2001:db8::1",
			expectErr:  true,
			expectedIP: "",
		},
		"Valid IPv4 CIDR but wrong version": {
			ipVersion:  ipv6,
			value:      "1.2.3.0/24",
			expectErr:  true,
			expectedIP: "",
		},
		"Valid IPv6 CIDR but wrong version": {
			ipVersion:  ipv4,
			value:      "2001:db8::/64",
			expectErr:  true,
			expectedIP: "",
		},
		"Empty value": {
			ipVersion:  ipv4,
			value:      "",
			expectErr:  true,
			expectedIP: "",
		},
		"Invalid value": {
			ipVersion:  ipv4,
			value:      "invalid_value",
			expectErr:  true,
			expectedIP: "",
		},
	} {
		t.Run(description, func(t *testing.T) {
			ipsMap := make(map[string]struct{})

			err := s.spf2IPResolver.addIPOrCIDRToSet(tc.ipVersion, tc.value, ipsMap)

			assert.Equal(t, tc.expectErr, err != nil)

			if tc.expectErr {
				assert.Empty(t, ipsMap, tc.expectedIP)
			} else {
				assert.Contains(t, ipsMap, tc.expectedIP)
			}
		})
	}
}
