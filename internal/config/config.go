// Package config handles YAML configuration loading, validation,
// and CLI flag overrides for the ech-middle proxy.
package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// --- Inbound ---
type HTTPConfig struct {
	Listen string `yaml:"listen"`
}
type SOCKS5Config struct {
	Listen string `yaml:"listen"`
}
type InboundConfig struct {
	HTTP   HTTPConfig   `yaml:"http"`
	SOCKS5 SOCKS5Config `yaml:"socks5"`
}

// --- Access ---
type AuthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
type AccessConfig struct {
	IPAllow    []string   `yaml:"ip_allow"`
	HTTPAuth   AuthConfig `yaml:"http_auth"`
	SOCKS5Auth AuthConfig `yaml:"socks5_auth"`
}

// --- Outbound ---
type DNSConfig struct {
	IntranetSafe bool     `yaml:"intranet_safe"`
	Servers      []string `yaml:"servers"`
}
type TimeoutConfig struct {
	DNS  int `yaml:"dns"`
	TLS  int `yaml:"tls"`
	Idle int `yaml:"idle"`
}
type OutboundConfig struct {
	Interface string        `yaml:"interface"`
	DNS       DNSConfig     `yaml:"dns"`
	Timeout   TimeoutConfig `yaml:"timeout"`
}

// --- ECH ---
type ECHConfig struct {
	Mode      string            `yaml:"mode"`
	Inject    map[string]string `yaml:"inject"`
	FileWatch int               `yaml:"file_watch"`
}

// --- CF Module ---
type CFConfig struct {
	Enabled      bool     `yaml:"enabled"`
	ECHConfig    string   `yaml:"ech_config"`
	AutoDiscover bool     `yaml:"auto_discover"`
	DiscoverFrom []string `yaml:"discover_from"`
	IPRanges     []string `yaml:"ip_ranges"`
	IPPrefer     []string `yaml:"ip_prefer"`
}

// --- Runtime ---
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
	Color bool   `yaml:"color"`
}
type RuntimeConfig struct {
	CADir           string    `yaml:"ca_dir"`
	Shutdown        string    `yaml:"shutdown"`
	ShutdownTimeout int       `yaml:"shutdown_timeout"`
	Log             LogConfig `yaml:"log"`
}

// --- Top-level Config ---
type Config struct {
	Inbound  InboundConfig  `yaml:"inbound"`
	Access   AccessConfig   `yaml:"access"`
	Outbound OutboundConfig `yaml:"outbound"`
	ECH      ECHConfig      `yaml:"ech"`
	CF       CFConfig       `yaml:"cf"`
	Runtime  RuntimeConfig  `yaml:"runtime"`
}

const DefaultConfigFilePath = "./ech-middle.yaml"

// DefaultConfig returns a Config populated with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Inbound: InboundConfig{
			HTTP:   HTTPConfig{Listen: ":8080"},
			SOCKS5: SOCKS5Config{Listen: ":1080"},
		},
		Access: AccessConfig{
			IPAllow:    []string{},
			HTTPAuth:   AuthConfig{Enabled: false},
			SOCKS5Auth: AuthConfig{Enabled: false},
		},
		Outbound: OutboundConfig{
			DNS: DNSConfig{
				IntranetSafe: false,
				Servers:      []string{"https://v.recipes/dns/cloudflare-dns.com/dns-query"},
			},
			Timeout: TimeoutConfig{DNS: 5, TLS: 10, Idle: 120},
		},
		ECH: ECHConfig{
			Mode:      "strict",
			Inject:    make(map[string]string),
			FileWatch: 30,
		},
		CF: CFConfig{
			Enabled:      false,
			AutoDiscover: true,
			DiscoverFrom: []string{"crypto.cloudflare.com"},
		},
		Runtime: RuntimeConfig{
			Shutdown:        "immediate",
			ShutdownTimeout: 30,
			Log:             LogConfig{Level: "info", Color: true},
		},
	}
}

// --- File Loading ---
func findConfigFile(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	if _, err := os.Stat(DefaultConfigFilePath); err == nil {
		return DefaultConfigFilePath
	}
	home, err := os.UserHomeDir()
	if err == nil {
		alt := filepath.Join(home, ".ech-middle", "config.yaml")
		if _, err := os.Stat(alt); err == nil {
			return alt
		}
	}
	return DefaultConfigFilePath
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	filePath := findConfigFile(path)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if path == "" {
			return cfg, nil
		}
		return nil, fmt.Errorf("cannot read config file %q: %w", filePath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("invalid YAML in %q: %w", filePath, err)
	}

	if cfg.ECH.Inject == nil {
		cfg.ECH.Inject = make(map[string]string)
	}
	if cfg.ECH.FileWatch != 0 && cfg.ECH.FileWatch < 5 {
		cfg.ECH.FileWatch = 5
	}

	return cfg, nil
}

// --- Validation ---
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"fc00::/7", "fe80::/10",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func isLoopbackIP(ip net.IP) bool { return ip.IsLoopback() }

func validateDNS(cfg DNSConfig) error {
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("outbound.dns.servers must not be empty (DNS is required for IP resolution; ECHConfig contains only public keys, not IP addresses)")
	}
	for _, s := range cfg.Servers {
		switch {
		case strings.HasPrefix(s, "https://"):
		case s == "system":
			if !cfg.IntranetSafe {
				return fmt.Errorf("dns server 'system' requires intranet_safe: true")
			}
		default:
			host, _, err := net.SplitHostPort(s)
			if err != nil {
				host = s
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("dns server %q is not a valid IP or DoH URL", s)
			}
			if isLoopbackIP(ip) {
				continue
			}
			if !isPrivateIP(ip) {
				return fmt.Errorf("public IP %q is not allowed as a UDP DNS server", s)
			}
			if !cfg.IntranetSafe {
				return fmt.Errorf("UDP DNS server %q requires intranet_safe: true", s)
			}
		}
	}
	return nil
}

func checkDoHConnectivity(dohURLs []string) error {
	if len(dohURLs) == 0 {
		return nil
	}
	var lastErr error
	reachable := 0
	for _, rawURL := range dohURLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			lastErr = fmt.Errorf("invalid DoH URL %q: %w", rawURL, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-message")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("DoH %q unreachable: %w", rawURL, err)
			continue
		}
		resp.Body.Close()
		reachable++
	}
	if reachable == 0 && lastErr != nil {
		return fmt.Errorf("no DoH servers reachable (last error: %w)", lastErr)
	}
	return nil
}

func ensureDir(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	tmpFile := filepath.Join(path, ".ech-middle-write-test")
	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("directory %q is not writable: %w", path, err)
	}
	f.Close()
	os.Remove(tmpFile)
	return nil
}

func (c *Config) Validate() error {
	if err := validateDNS(c.Outbound.DNS); err != nil {
		return err
	}

	var dohURLs []string
	for _, s := range c.Outbound.DNS.Servers {
		if strings.HasPrefix(s, "https://") {
			dohURLs = append(dohURLs, s)
		}
	}
	if err := checkDoHConnectivity(dohURLs); err != nil {
		return fmt.Errorf("DoH connectivity check failed: %w", err)
	}

	caDir := c.Runtime.CADir
	if caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory for CA: %w", err)
		}
		caDir = filepath.Join(home, ".ech-middle")
	}
	if err := ensureDir(caDir); err != nil {
		return fmt.Errorf("CA directory %q: %w", caDir, err)
	}

	for _, addr := range []string{c.Inbound.HTTP.Listen, c.Inbound.SOCKS5.Listen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("invalid listen address %q: %w", addr, err)
		}
	}

	// Verify the outbound interface exists on this system.
	if c.Outbound.Interface != "" {
		if _, err := net.InterfaceByName(c.Outbound.Interface); err != nil {
			return fmt.Errorf("outbound interface %q not found: %w", c.Outbound.Interface, err)
		}
	}

	return nil
}

// --- CLI Override Helpers ---
type CLIOverrides struct {
	ConfigPath  string
	HTTPListen  string
	SOCKSListen string
	DNS         []string
	ECHMode     string
	LogLevel    string
	LogFile     string
	Verbose     bool // note: spelling preserved for CLI compatibility
}

func (c *Config) ApplyCLI(o CLIOverrides) {
	if o.HTTPListen != "" {
		c.Inbound.HTTP.Listen = o.HTTPListen
	}
	if o.SOCKSListen != "" {
		c.Inbound.SOCKS5.Listen = o.SOCKSListen
	}
	if len(o.DNS) > 0 {
		c.Outbound.DNS.Servers = append([]string{}, o.DNS...)
	}
	if o.ECHMode != "" {
		c.ECH.Mode = o.ECHMode
	}
	if o.Verbose {
		c.Runtime.Log.Level = "debug"
	}
	if o.LogLevel != "" {
		c.Runtime.Log.Level = o.LogLevel
	}
	if o.LogFile != "" {
		c.Runtime.Log.File = o.LogFile
	}
}

// --- Helpers ---
func (c *Config) Strict() bool           { return c.ECH.Mode == "strict" }
func (c *Config) OutboundInterface() string { return c.Outbound.Interface }
