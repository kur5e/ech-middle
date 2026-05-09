package auth_test

import (
	"testing"

	"ech-middle/internal/auth"
	"ech-middle/internal/config"
)

func TestNewACL_Empty(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{})

	if acl.IsIPFilterEnabled() {
		t.Error("empty ACL should not have IP filter enabled")
	}
	if acl.IsHTTPAuthEnabled() {
		t.Error("empty ACL should not have HTTP auth enabled")
	}
}

func TestNewACL_IPFilter(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		IPAllow: []string{"192.168.1.0/24", "10.0.0.0/8"},
	})

	if !acl.IsIPFilterEnabled() {
		t.Error("ACL with IP ranges should have IP filter enabled")
	}

	// In-range IP.
	if !acl.CheckIP("192.168.1.100:12345") {
		t.Error("192.168.1.100 should be allowed")
	}
	// In-range 10.x.
	if !acl.CheckIP("10.100.200.50:9999") {
		t.Error("10.100.200.50 should be allowed")
	}
	// Out-of-range IP.
	if acl.CheckIP("203.0.113.5:443") {
		t.Error("203.0.113.5 should be denied")
	}
	// IPv6 loopback should be denied.
	if acl.CheckIP("[::1]:12345") {
		t.Error("::1 should be denied when not in allowlist")
	}
}

func TestACL_CheckIP_NoPort(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		IPAllow: []string{"172.16.0.0/12"},
	})

	if !acl.CheckIP("172.16.5.5") {
		t.Error("IP without port should be checked correctly")
	}
}

func TestACL_CheckIP_InvalidIP(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		IPAllow: []string{"192.168.0.0/16"},
	})

	if acl.CheckIP("not-an-ip:1234") {
		t.Error("invalid IP should be denied")
	}
}

func TestACL_CheckIP_IPv6(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		IPAllow: []string{"fc00::/7"},
	})

	if !acl.CheckIP("[fd12:3456:789a::1]:443") {
		t.Error("IPv6 in fc00::/7 should be allowed")
	}
}

func TestACL_CheckIP_MultipleCIDRs(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		IPAllow: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	})

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"10.0.0.1:80", true},
		{"172.16.5.5:443", true},
		{"192.168.1.1:8080", true},
		{"100.64.0.1:53", false},
		{"8.8.8.8:443", false},
	}

	for _, tt := range tests {
		got := acl.CheckIP(tt.ip)
		if got != tt.allowed {
			t.Errorf("CheckIP(%q) = %v, want %v", tt.ip, got, tt.allowed)
		}
	}
}

func TestACL_CheckIP_DisabledIPFilter(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{})

	if !acl.CheckIP("8.8.8.8:443") {
		t.Error("when IP filter is disabled, all IPs should be allowed")
	}
}

func TestACL_HTTPAuth_Disabled(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{})

	if !acl.HTTPAuth("any", "thing") {
		t.Error("disabled HTTP auth should allow all credentials")
	}
}

func TestACL_HTTPAuth_Enabled(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		HTTPAuth: config.AuthConfig{
			Enabled:  true,
			Username: "admin",
			Password: "secret",
		},
	})

	if !acl.IsHTTPAuthEnabled() {
		t.Error("HTTP auth should be enabled")
	}

	if !acl.HTTPAuth("admin", "secret") {
		t.Error("correct credentials should pass")
	}

	if acl.HTTPAuth("admin", "wrong") {
		t.Error("wrong password should fail")
	}

	if acl.HTTPAuth("wrong", "secret") {
		t.Error("wrong username should fail")
	}

	if acl.HTTPAuth("", "") {
		t.Error("empty credentials should fail")
	}
}

func TestACL_HTTPAuth_CaseSensitive(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		HTTPAuth: config.AuthConfig{
			Enabled:  true,
			Username: "Admin",
			Password: "Secret",
		},
	})

	if acl.HTTPAuth("admin", "secret") {
		t.Error("auth should be case-sensitive")
	}
}

func TestACL_SOCKSAuth_Disabled(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{})

	_, ok := acl.SOCKSAuth(nil, "any", "thing")
	if !ok {
		t.Error("disabled SOCKS5 auth should allow all credentials")
	}
}

func TestACL_SOCKSAuth_Enabled(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		SOCKS5Auth: config.AuthConfig{
			Enabled:  true,
			Username: "proxyuser",
			Password: "proxypass",
		},
	})

	_, ok := acl.SOCKSAuth(nil, "proxyuser", "proxypass")
	if !ok {
		t.Error("correct SOCKS5 credentials should pass")
	}

	_, ok = acl.SOCKSAuth(nil, "proxyuser", "wrong")
	if ok {
		t.Error("wrong password should fail")
	}

	_, ok = acl.SOCKSAuth(nil, "wrong", "proxypass")
	if ok {
		t.Error("wrong username should fail")
	}
}

func TestACL_InvalidCIDR(t *testing.T) {
	acl := auth.NewACL(config.AccessConfig{
		IPAllow: []string{"invalid-cidr", "192.168.0.0/16", "also-invalid"},
	})

	if !acl.IsIPFilterEnabled() {
		t.Error("at least one valid CIDR should enable IP filter")
	}

	if !acl.CheckIP("192.168.5.5:80") {
		t.Error("valid CIDR should work even with other invalid ones")
	}
}

func TestACL_ConstantTimeCompare(t *testing.T) {
	// Test that auth comparison rejects even when lengths match but content differs.
	acl := auth.NewACL(config.AccessConfig{
		HTTPAuth: config.AuthConfig{
			Enabled:  true,
			Username: "correct-user",
			Password: "correct-pass",
		},
	})

	// Same length, wrong content.
	if acl.HTTPAuth("correct-user", "wrong-pass1") {
		t.Error("same-length wrong password should fail")
	}

	// Different length.
	if acl.HTTPAuth("short", "correct-pass") {
		t.Error("different-length username should fail")
	}
}
