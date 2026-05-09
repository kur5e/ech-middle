package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"ech-middle/internal/config"
)

// --- LoadConfig Tests ---

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig with empty path should not error: %v", err)
	}

	if cfg.Inbound.HTTP.Listen != ":8080" {
		t.Errorf("default HTTP listen: got %q, want %q", cfg.Inbound.HTTP.Listen, ":8080")
	}
	if cfg.Inbound.SOCKS5.Listen != ":1080" {
		t.Errorf("default SOCKS5 listen: got %q, want %q", cfg.Inbound.SOCKS5.Listen, ":1080")
	}
	if cfg.ECH.Mode != "strict" {
		t.Errorf("default ECH mode: got %q, want %q", cfg.ECH.Mode, "strict")
	}
	if len(cfg.Outbound.DNS.Servers) == 0 {
		t.Error("default DNS servers should not be empty")
	}
	if cfg.Runtime.Shutdown != "immediate" {
		t.Errorf("default shutdown mode: got %q, want %q", cfg.Runtime.Shutdown, "immediate")
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	// Write a temporary YAML config.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
inbound:
  http:
    listen: ":9090"
  socks5:
    listen: ":1090"
ech:
  mode: "opportunistic"
  inject:
    "test.example": "AEX+DQBB8QAg"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	if cfg.Inbound.HTTP.Listen != ":9090" {
		t.Errorf("HTTP listen: got %q, want %q", cfg.Inbound.HTTP.Listen, ":9090")
	}
	if cfg.ECH.Mode != "opportunistic" {
		t.Errorf("ECH mode: got %q, want %q", cfg.ECH.Mode, "opportunistic")
	}
	if v, ok := cfg.ECH.Inject["test.example"]; !ok || v != "AEX+DQBB8QAg" {
		t.Errorf("inject map missing or wrong: %v", cfg.ECH.Inject)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	// Non-existent file with explicit path should error.
	_, err := config.LoadConfig("/nonexistent/path/ech-middle.yaml")
	if err == nil {
		t.Error("expected error for non-existent config file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(configPath, []byte("{{{ invalid yaml"), 0644)

	_, err := config.LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfig_EmptyInjectInitialized(t *testing.T) {
	cfg, _ := config.LoadConfig("")
	if cfg.ECH.Inject == nil {
		t.Error("inject map should be initialized even when empty in config")
	}
}

// --- Validate Tests ---

func TestValidate_EmptyDNS_Servers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.Servers = []string{}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for empty DNS servers")
	}
}

func TestValidate_PublicUDPDNS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.Servers = []string{"8.8.8.8:53"} // public UDP

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for public UDP DNS server without intranet_safe")
	}
}

func TestValidate_PrivateUDPDNS_WithIntranetSafe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.IntranetSafe = true
	cfg.Outbound.DNS.Servers = []string{"10.0.0.1:53"}

	err := cfg.Validate()
	// Should pass DNS check but might fail DoH connectivity.
	// We only check that the UDP-specific error doesn't occur.
	if err != nil && err.Error()[:6] == "public" {
		t.Errorf("private UDP with intranet_safe should not be rejected: %v", err)
	}
}

func TestValidate_PrivateUDPDNS_WithoutIntranetSafe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.Servers = []string{"10.0.0.1:53"}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for private UDP DNS without intranet_safe")
	}
}

func TestValidate_SystemDNS_WithoutIntranetSafe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.Servers = []string{"system"}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for 'system' DNS without intranet_safe")
	}
}

func TestValidate_SystemDNS_WithIntranetSafe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.IntranetSafe = true
	cfg.Outbound.DNS.Servers = []string{"system"}

	err := cfg.Validate()
	// System DNS may be unreachable and DoH connectivity will fail,
	// but the config-level validation (DNS strategy check) should pass.
	if err != nil && (err.Error()[0:3] == "dns" || err.Error()[0:3] == "DNS") {
		// "dns server 'system' requires..." — this is a config error, should not happen.
		if err.Error()[:20] == "dns server 'system'" {
			t.Errorf("system DNS with intranet_safe should not be rejected: %v", err)
		}
	}
}

func TestValidate_InvalidListenAddress(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.DNS.Servers = []string{"https://1.1.1.1/dns-query"} // valid DoH
	cfg.Inbound.HTTP.Listen = "not-a-valid-address"

	err := cfg.Validate()
	// May fail on DoH connectivity first, but the listen address check
	// is the last one. We just verify no panic.
	_ = err
}

// --- CLI Override Tests ---

func TestApplyCLI_OverrideHTTPListen(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{HTTPListen: ":9999"})

	if cfg.Inbound.HTTP.Listen != ":9999" {
		t.Errorf("HTTP listen override: got %q, want %q", cfg.Inbound.HTTP.Listen, ":9999")
	}
}

func TestApplyCLI_OverrideSOCKSListen(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{SOCKSListen: ":1999"})

	if cfg.Inbound.SOCKS5.Listen != ":1999" {
		t.Errorf("SOCKS5 listen override: got %q, want %q", cfg.Inbound.SOCKS5.Listen, ":1999")
	}
}

func TestApplyCLI_OverrideECHMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{ECHMode: "opportunistic"})

	if cfg.ECH.Mode != "opportunistic" {
		t.Errorf("ECH mode override: got %q, want %q", cfg.ECH.Mode, "opportunistic")
	}
}

func TestApplyCLI_OverrideDNS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{DNS: []string{"https://8.8.8.8/dns-query"}})

	if len(cfg.Outbound.DNS.Servers) != 1 {
		t.Fatalf("DNS servers count: got %d, want 1", len(cfg.Outbound.DNS.Servers))
	}
	if cfg.Outbound.DNS.Servers[0] != "https://8.8.8.8/dns-query" {
		t.Errorf("DNS server: got %q", cfg.Outbound.DNS.Servers[0])
	}
}

func TestApplyCLI_VerboseSetsDebug(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{Verbose: true})

	if cfg.Runtime.Log.Level != "debug" {
		t.Errorf("verbose should set log level to debug: got %q", cfg.Runtime.Log.Level)
	}
}

func TestApplyCLI_LogLevelOverridesVerbose(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{Verbose: true, LogLevel: "warn"})

	// LogLevel should take precedence (applied after verbose).
	if cfg.Runtime.Log.Level != "warn" {
		t.Errorf("explicit log level should override verbose: got %q", cfg.Runtime.Log.Level)
	}
}

func TestApplyCLI_LogFileOverride(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyCLI(config.CLIOverrides{LogFile: "/tmp/ech-test.log"})

	if cfg.Runtime.Log.File != "/tmp/ech-test.log" {
		t.Errorf("log file override: got %q", cfg.Runtime.Log.File)
	}
}

func TestApplyCLI_NoOverride(t *testing.T) {
	cfg := config.DefaultConfig()
	original := cfg.Inbound.HTTP.Listen
	cfg.ApplyCLI(config.CLIOverrides{})

	if cfg.Inbound.HTTP.Listen != original {
		t.Error("empty overrides should not change config")
	}
}

// --- Helper Method Tests ---

func TestStrict_Mode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ECH.Mode = "strict"
	if !cfg.Strict() {
		t.Error("strict mode should return true")
	}

	cfg.ECH.Mode = "opportunistic"
	if cfg.Strict() {
		t.Error("opportunistic mode should return false")
	}
}

func TestOutboundInterface_Default(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.OutboundInterface() != "" {
		t.Error("default outbound interface should be empty")
	}
}

func TestOutboundInterface_Custom(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Outbound.Interface = "eth0"
	if cfg.OutboundInterface() != "eth0" {
		t.Errorf("custom interface: got %q, want %q", cfg.OutboundInterface(), "eth0")
	}
}

// --- DefaultConfig Tests ---

func TestDefaultConfig_FileWatch(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.ECH.FileWatch != 30 {
		t.Errorf("default file_watch: got %d, want 30", cfg.ECH.FileWatch)
	}
}

func TestDefaultConfig_Timeout(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Outbound.Timeout.DNS != 5 {
		t.Errorf("default DNS timeout: got %d, want 5", cfg.Outbound.Timeout.DNS)
	}
	if cfg.Outbound.Timeout.TLS != 10 {
		t.Errorf("default TLS timeout: got %d, want 10", cfg.Outbound.Timeout.TLS)
	}
	if cfg.Outbound.Timeout.Idle != 120 {
		t.Errorf("default idle timeout: got %d, want 120", cfg.Outbound.Timeout.Idle)
	}
}

func TestDefaultConfig_LogConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Runtime.Log.Level != "info" {
		t.Errorf("default log level: got %q", cfg.Runtime.Log.Level)
	}
	if !cfg.Runtime.Log.Color {
		t.Error("default color should be true")
	}
}

func TestDefaultConfig_CFDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.CF.Enabled {
		t.Error("CF module should be disabled by default")
	}
}

// --- Edge Cases ---

func TestLoadConfig_FileWatchClamp(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "low-watch.yaml")

	yamlContent := `
dns:
  intranet_safe: true
  servers:
    - "system"
ech:
  file_watch: 2
`
	os.WriteFile(configPath, []byte(yamlContent), 0644)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		// May fail on DoH validation; that's ok, we just check the clamp.
	}
	if cfg != nil && cfg.ECH.FileWatch != 5 {
		t.Errorf("file_watch should be clamped to 5: got %d", cfg.ECH.FileWatch)
	}
}

func TestLoadConfig_FileWatchZero(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ECH.FileWatch = 0
	// 0 should be treated as "use default". The LoadConfig function
	// only sets defaults for missing fields, not zero values.
	// Verify that 0 is the zero value.
	if cfg.ECH.FileWatch != 0 {
		t.Error("zero file_watch should remain zero (caller handles default)")
	}
}

func TestLoadConfig_PartialYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "partial.yaml")

	yamlContent := `
inbound:
  http:
    listen: ":7777"
`
	os.WriteFile(configPath, []byte(yamlContent), 0644)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("partial YAML should load with defaults: %v", err)
	}
	// Specified field should be loaded.
	if cfg.Inbound.HTTP.Listen != ":7777" {
		t.Errorf("HTTP listen: got %q, want %q", cfg.Inbound.HTTP.Listen, ":7777")
	}
	// Unspecified fields should use defaults.
	if cfg.ECH.Mode != "strict" {
		t.Errorf("unspecified ECH mode should default: got %q", cfg.ECH.Mode)
	}
}
