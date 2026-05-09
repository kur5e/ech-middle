// Package auth provides access control for the proxy, combining
// IP allowlist (CIDR) matching, HTTP Basic Authentication, and
// SOCKS5 username/password authentication into a single ACL.
package auth

import (
	"context"
	"net"
	"strings"

	"ech-middle/internal/config"
)

// ACL holds access control rules for the proxy.
type ACL struct {
	ipAllow    []*net.IPNet
	ipEnabled  bool

	httpUser string
	httpPass string
	httpAuth bool

	socks5User string
	socks5Pass string
	socks5Auth bool
}

// NewACL creates an ACL from the provided access configuration.
func NewACL(cfg config.AccessConfig) *ACL {
	a := &ACL{
		httpUser:   cfg.HTTPAuth.Username,
		httpPass:   cfg.HTTPAuth.Password,
		httpAuth:   cfg.HTTPAuth.Enabled,
		socks5User: cfg.SOCKS5Auth.Username,
		socks5Pass: cfg.SOCKS5Auth.Password,
		socks5Auth: cfg.SOCKS5Auth.Enabled,
	}

	for _, cidr := range cfg.IPAllow {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		a.ipAllow = append(a.ipAllow, ipNet)
	}
	if len(a.ipAllow) > 0 {
		a.ipEnabled = true
	}

	return a
}

// CheckIP returns true if the remote address is allowed. Extracts
// the IP from host:port format, and matches against the allowlist.
// Returns true when IP filtering is not enabled (allow all).
func (a *ACL) CheckIP(remoteAddr string) bool {
	if !a.ipEnabled {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, ipNet := range a.ipAllow {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// HTTPAuth validates HTTP Basic Authentication credentials.
// Returns true when HTTP auth is not enabled (allow all).
func (a *ACL) HTTPAuth(user, pass string) bool {
	if !a.httpAuth {
		return true
	}
	return subtleConstantTimeCompare(user, a.httpUser) &&
		subtleConstantTimeCompare(pass, a.httpPass)
}

// SOCKSAuth validates SOCKS5 username/password credentials.
// The boolean return value indicates whether authentication succeeded.
// When SOCKS5 auth is not enabled, all connections are allowed.
func (a *ACL) SOCKSAuth(_ context.Context, user, pass string) (context.Context, bool) {
	if !a.socks5Auth {
		return context.Background(), true
	}
	ok := subtleConstantTimeCompare(user, a.socks5User) &&
		subtleConstantTimeCompare(pass, a.socks5Pass)
	return context.Background(), ok
}

// IsHTTPAuthEnabled returns true if HTTP Basic Auth is active.
func (a *ACL) IsHTTPAuthEnabled() bool {
	return a.httpAuth
}

// IsIPFilterEnabled returns true if IP allowlist filtering is active.
func (a *ACL) IsIPFilterEnabled() bool {
	return a.ipEnabled
}

// subtleConstantTimeCompare performs a constant-time string comparison
// to prevent timing attacks on authentication credentials.
func subtleConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
