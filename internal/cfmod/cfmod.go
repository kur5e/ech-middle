// Package cfmod implements a Cloudflare ECH module that auto-detects
// CF-proxied websites and injects CF's unified ECHConfig to enable ECH
// even when the site owner hasn't explicitly enabled it in the CF dashboard.
//
// The module implements the ECHProvider interface and is registered with
// the resolver. When enabled=false, the factory returns nil and the
// resolver incurs zero overhead from this module.
package cfmod

import (
	"context"
	"net"

	"ech-middle/internal/config"
)

// Built-in Cloudflare IPv4 address ranges.
// Source: https://www.cloudflare.com/ips-v4
var builtinCFIPv4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// Built-in Cloudflare IPv6 address ranges.
// Source: https://www.cloudflare.com/ips-v6
var builtinCFIPv6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// CFModule implements ECHProvider for Cloudflare-proxied websites.
type CFModule struct {
	enabled   bool
	echConfig []byte
	ipNets    []*net.IPNet
	ipPrefer  []net.IP
}

// New creates a CFModule from configuration. Returns nil if enabled is false,
// allowing the caller to skip registration entirely.
func New(cfg config.CFConfig) (*CFModule, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	m := &CFModule{
		enabled: true,
	}

	// Parse IP ranges — use built-in if user provided none.
	ipRanges := cfg.IPRanges
	if len(ipRanges) == 0 {
		ipRanges = append(ipRanges, builtinCFIPv4...)
		ipRanges = append(ipRanges, builtinCFIPv6...)
	}

	for _, cidr := range ipRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		m.ipNets = append(m.ipNets, ipNet)
	}

	// Parse preferred IPs.
	for _, ipStr := range cfg.IPPrefer {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			m.ipPrefer = append(m.ipPrefer, ip)
		}
	}

	// ECHConfig will be set later via SetECHConfig after auto-discovery
	// or from the config directly in main's startup sequence.
	return m, nil
}

// SetECHConfig stores the module's ECHConfig (called after auto-discovery
// or when loaded from config). The data should be the raw ECHConfigList bytes.
func (m *CFModule) SetECHConfig(data []byte) {
	m.echConfig = data
}

// Name returns the provider identifier.
func (m *CFModule) Name() string {
	return "cf"
}

// Match checks whether the given hostname resolves to a Cloudflare IP.
// The resolver already resolved A/AAAA and passes the IP list to avoid
// duplicate DNS queries.
func (m *CFModule) Match(_ context.Context, _ string, ips []net.IP) ([]byte, bool) {
	if !m.enabled || len(m.echConfig) == 0 {
		return nil, false
	}

	for _, ip := range ips {
		if m.isCFIP(ip) {
			return m.echConfig, true
		}
	}
	return nil, false
}

// PreferIPs returns the preferred CF edge IPs for this module.
func (m *CFModule) PreferIPs() []net.IP {
	return m.ipPrefer
}

// IsCFIP checks if a single IP falls within any configured CF range.
func (m *CFModule) IsCFIP(ip net.IP) bool {
	return m.isCFIP(ip)
}

// isCFIP is the internal implementation of CF IP range matching.
func (m *CFModule) isCFIP(ip net.IP) bool {
	for _, ipNet := range m.ipNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
