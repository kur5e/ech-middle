// Package echconfig resolves ECH (Encrypted Client Hello) configurations
// for target hostnames via DNS-over-HTTPS (DoH), with fallback to system
// DNS or local UDP when intranet-safe mode is enabled. It supports manual
// config injection, pluggable CDN providers, file hot-reload, and a
// stale-while-revalidate cache with singleflight deduplication.
package echconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"ech-middle/internal/config"
)

// DNSMode represents the transport mode for DNS queries.
type DNSMode int

const (
	DNSModeDoH    DNSMode = iota // DNS-over-HTTPS (RFC 8484)
	DNSModeSystem                // operating system DNS (requires intranet-safe)
	DNSModeUDP                   // traditional UDP:53 (private IPs only, requires intranet-safe)
)

// DNSServer represents a configured DNS server.
type DNSServer struct {
	URL     string   // DoH: "https://1.1.1.1/dns-query"; UDP: "10.0.0.1:53"; System: "system"
	Mode    DNSMode
	Healthy atomic.Bool // connectivity check result
}

// ECHProvider is the interface for external ECH config providers (e.g., CF module).
// The Resolver resolves A/AAAA records and passes the IP list to Match() to avoid
// duplicate DNS queries.
type ECHProvider interface {
	Name() string
	Match(ctx context.Context, hostname string, ips []net.IP) ([]byte, bool)
	PreferIPs() []net.IP
}

// ECHResult encapsulates the resolved ECH configuration and optional dial hints.
type ECHResult struct {
	Config    []byte   // raw ECHConfigList bytes (may be nil when no ECH is available)
	PreferIPs []net.IP // preferred IPs for dialing (empty = use DNS-resolved IPs)
	Source    string   // "dns" | "inject" | "cf" (for logging)
}

// cacheEntry holds a cached ECHResult with its expiry time.
type cacheEntry struct {
	result    *ECHResult
	expiresAt time.Time
	createdAt time.Time
}

// Resolver discovers and caches ECH configurations for target hostnames.
type Resolver struct {
	servers   []*DNSServer
	inject    map[string]*echSource
	providers []ECHProvider
	cache     map[string]*cacheEntry
	cacheMu   sync.RWMutex

	dohClient *http.Client
	sfGroup   singleflight.Group
	watcher   *fileWatcher
	strict    bool
}

// NewResolver creates a Resolver from the provided DNS and ECH configuration.
// Optional ECHProvider instances (e.g., CF module) are registered for fallback
// when a DNS HTTPS record does not contain an ECHConfig.
func NewResolver(dnsCfg config.DNSConfig, echCfg config.ECHConfig, providers ...ECHProvider) (*Resolver, error) {
	resolver := &Resolver{
		servers:   parseServers(dnsCfg),
		inject:    make(map[string]*echSource),
		providers: providers,
		cache:     make(map[string]*cacheEntry),
		dohClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		strict: echCfg.Mode == "strict",
	}

	// Parse inject map.
	for hostname, value := range echCfg.Inject {
		src, err := parseSource(value)
		if err != nil {
			return nil, fmt.Errorf("ech.inject[%q]: %w", hostname, err)
		}
		resolver.inject[hostname] = src
	}

	// Start file watcher if any inject values use @file:.
	fileWatch := echCfg.FileWatch
	if fileWatch == 0 {
		fileWatch = 30
	}
	if fileWatch < 5 {
		fileWatch = 5
	}

	var watched []*echSource
	for _, src := range resolver.inject {
		if src.filePath != "" {
			watched = append(watched, src)
		}
	}
	if len(watched) > 0 {
		resolver.watcher = newFileWatcher(watched, time.Duration(fileWatch)*time.Second)
		resolver.watcher.start()
	}

	return resolver, nil
}

// parseServers converts a DNS server list to DNSServer objects,
// classifying each entry by mode.
func parseServers(dnsCfg config.DNSConfig) []*DNSServer {
	var result []*DNSServer
	for _, s := range dnsCfg.Servers {
		ds := &DNSServer{URL: s}
		switch {
		case strings.HasPrefix(s, "https://"):
			ds.Mode = DNSModeDoH
		case s == "system":
			ds.Mode = DNSModeSystem
		default:
			ds.Mode = DNSModeUDP
		}
		ds.Healthy.Store(true) // assume healthy until proven otherwise
		result = append(result, ds)
	}
	return result
}

// GetECHConfig resolves the ECH configuration for a hostname.
// Priority: inject[hostname] > cache > DNS HTTPS record > ECHProvider > nil.
// In strict mode, returning a nil Config without error means "block the connection".
// In opportunistic mode, returning nil means "use plain TLS".
func (r *Resolver) GetECHConfig(ctx context.Context, hostname string) (*ECHResult, error) {
	// 1. Manual injection (exact hostname match).
	if src, ok := r.inject[hostname]; ok {
		return &ECHResult{Config: src.load(), Source: "inject"}, nil
	}

	// 2. Memory cache (stale-while-revalidate).
	r.cacheMu.RLock()
	entry, ok := r.cache[hostname]
	r.cacheMu.RUnlock()

	if ok {
		now := time.Now()
		if now.Before(entry.expiresAt) {
			// Fresh — return immediately.
			return entry.result, nil
		}
		// Moderately stale (< 4 hours after expiry) — return old + async refresh.
		if now.Before(entry.expiresAt.Add(4 * time.Hour)) {
			go r.asyncRefresh(hostname)
			return entry.result, nil
		}
		// Very stale — fall through to blocking refresh.
	}

	// 3. Blocking refresh with singleflight dedup.
	v, err, _ := r.sfGroup.Do(hostname, func() (interface{}, error) {
		return r.resolveBlocking(ctx, hostname)
	})
	if err != nil {
		return nil, err
	}
	return v.(*ECHResult), nil
}

// resolveBlocking performs a fresh DNS resolution for the hostname.
// It is called under singleflight protection to avoid duplicate queries.
func (r *Resolver) resolveBlocking(ctx context.Context, hostname string) (*ECHResult, error) {
	result, err := r.queryECHConfig(ctx, hostname)
	if err != nil {
		return nil, err
	}

	// Cache the result with TTL from the most recent query (or default).
	ttl := 300 * time.Second // default 5 minutes
	if result != nil && result.Config != nil {
		ttl = 3600 * time.Second // 1 hour for successful resolutions
	}

	r.cacheMu.Lock()
	r.cache[hostname] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
		createdAt: time.Now(),
	}
	r.cacheMu.Unlock()

	return result, nil
}

// queryECHConfig attempts to discover an ECH configuration for the hostname
// through DNS and then through registered providers.
func (r *Resolver) queryECHConfig(ctx context.Context, hostname string) (*ECHResult, error) {
	// 3a. Query DNS HTTPS record for ECHConfig.
	echConfig, err := r.resolveDoH(ctx, hostname)
	if err == nil && echConfig != nil {
		return &ECHResult{Config: echConfig, Source: "dns"}, nil
	}

	// 3b. No ECHConfig from DNS — try providers.
	ips, ipErr := r.resolveA(ctx, hostname)
	if ipErr != nil {
		// Can't resolve IPs either — fail.
		if r.strict {
			return nil, fmt.Errorf("no ECH config for %q and IP resolution failed: %w", hostname, ipErr)
		}
		// Opportunistic: return nil config (caller falls back to plain TLS).
		return &ECHResult{}, nil
	}

	for _, p := range r.providers {
			if p == nil {
				continue
			}
		if config, ok := p.Match(ctx, hostname, ips); ok {
			return &ECHResult{
				Config:    config,
				PreferIPs: p.PreferIPs(),
				Source:    p.Name(),
			}, nil
		}
	}

	// No provider matched.
	if r.strict {
		return nil, fmt.Errorf("no ECH config available for %q (strict mode)", hostname)
	}

	// Opportunistic mode: return nil config.
	return &ECHResult{}, nil
}

// resolveDoH queries DNS HTTPS (type 65) records for the hostname via DoH,
// system DNS, or UDP, falling through the server list in priority order.
func (r *Resolver) resolveDoH(ctx context.Context, hostname string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeHTTPS)
	msg.Id = 0     // RFC 8484: set ID to 0 for cache friendliness
	msg.RecursionDesired = true

	for _, srv := range r.servers {
		if !srv.Healthy.Load() {
			continue
		}

		var resp *dns.Msg
		var err error

		switch srv.Mode {
		case DNSModeDoH:
			resp, err = r.exchangeDoH(ctx, msg, srv.URL)
		case DNSModeSystem:
			resp, err = r.exchangeSystem(ctx, msg)
		case DNSModeUDP:
			resp, err = r.exchangeUDP(ctx, msg, srv.URL)
		}

		if err != nil {
			srv.Healthy.Store(false)
			continue
		}
		srv.Healthy.Store(true)

		config, err := parseHTTPSResponse(resp)
		if err != nil {
			continue // try next server
		}
		if config != nil {
			return config, nil
		}
		// No ECHConfig in this response — try next server.
	}

	return nil, fmt.Errorf("no ECH config found for %q from any DNS server", hostname)
}

// exchangeDoH performs a DNS-over-HTTPS query (RFC 8484).
func (r *Resolver) exchangeDoH(ctx context.Context, msg *dns.Msg, dohURL string) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %q failed: %w", dohURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("DoH response read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned %d", resp.StatusCode)
	}

	result := new(dns.Msg)
	if err := result.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DoH response failed: %w", err)
	}

	return result, nil
}

// exchangeSystem uses Go's built-in resolver (system DNS).
func (r *Resolver) exchangeSystem(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Use the miekg/dns client with the system resolver via a local forwarder.
	// For simplicity, we dial the system's default DNS via UDP.
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Attempt to resolve via common system DNS addresses.
	for _, addr := range []string{"127.0.0.1:53", "127.0.0.53:53"} {
		resp, _, err := c.Exchange(msg, addr)
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("system DNS unreachable")
}

// exchangeUDP performs a traditional DNS query over UDP port 53.
func (r *Resolver) exchangeUDP(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, error) {
	// Ensure the address includes port 53 if not already specified.
	if !strings.Contains(addr, ":") {
		addr = addr + ":53"
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		return nil, fmt.Errorf("UDP DNS query to %q failed: %w", addr, err)
	}

	return resp, nil
}

// resolveA resolves A and AAAA records for a hostname via DoH.
// Returns the resolved IP addresses.
func (r *Resolver) resolveA(ctx context.Context, hostname string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.Id = 0
	msg.RecursionDesired = true

	for _, srv := range r.servers {
		if !srv.Healthy.Load() {
			continue
		}

		var resp *dns.Msg
		var err error

		switch srv.Mode {
		case DNSModeDoH:
			resp, err = r.exchangeDoH(ctx, msg, srv.URL)
		case DNSModeSystem:
			resp, err = r.exchangeSystem(ctx, msg)
		case DNSModeUDP:
			resp, err = r.exchangeUDP(ctx, msg, srv.URL)
		}

		if err != nil {
			continue
		}

		var ips []net.IP
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
			}
		}

		if len(ips) > 0 {
			return ips, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve A/AAAA for %q", hostname)
}

// parseHTTPSResponse extracts ECHConfigList from a DNS HTTPS response.
// Returns nil, nil if the HTTPS record exists but has no ECH SvcParam.
func parseHTTPSResponse(resp *dns.Msg) ([]byte, error) {
	for _, ans := range resp.Answer {
		https, ok := ans.(*dns.HTTPS)
		if !ok {
			continue
		}

		// Handle Alias mode (Priority == 0): record provides an alias target,
		// the caller should recurse. For now, we skip and let the next
		// resolution attempt handle it (simplifies the initial implementation).
		if https.Priority == 0 {
			continue
		}

		// Service mode (Priority > 0): extract ECH SvcParam (key 5).
		for _, kv := range https.Value {
			if kv.Key() == dns.SVCB_ECHCONFIG {
				if echKV, ok := kv.(*dns.SVCBECHConfig); ok {
					return echKV.ECH, nil
				}
			}
		}
	}
	// No HTTPS record or no ECH config found.
	return nil, nil
}

// asyncRefresh performs a non-blocking cache refresh.
func (r *Resolver) asyncRefresh(hostname string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = r.resolveBlocking(ctx, hostname)
}

// HandleRetry updates the cache with an ECHConfig returned in an
// ECHRejectionError's RetryConfigList.
func (r *Resolver) HandleRetry(hostname string, retryConfigList []byte) {
	r.cacheMu.Lock()
	r.cache[hostname] = &cacheEntry{
		result:    &ECHResult{Config: retryConfigList, Source: "retry"},
		expiresAt: time.Now().Add(300 * time.Second),
		createdAt: time.Now(),
	}
	r.cacheMu.Unlock()
}

// Shutdown stops background goroutines (file watcher).
func (r *Resolver) Shutdown() {
	if r.watcher != nil {
		r.watcher.stop()
	}
}

// --- ECH Source (inline / @file) ---

// echSource represents a single ECH config value, either inline or file-backed.
type echSource struct {
	value    atomic.Value // stores []byte
	filePath string       // empty = inline mode
	mu       sync.Mutex   // protects hot-reload writes
}

// parseSource parses an inject value. If it starts with "@file:", it is
// treated as a file path; otherwise it is treated as inline base64.
func parseSource(value string) (*echSource, error) {
	src := &echSource{}

	if strings.HasPrefix(value, "@file:") {
		src.filePath = value[len("@file:"):]
		data, err := os.ReadFile(src.filePath)
		if err != nil {
			return nil, fmt.Errorf("cannot read ech config file %q: %w", src.filePath, err)
		}
		src.value.Store(decodeBase64OrRaw(data))
	} else {
		src.value.Store(decodeBase64OrRaw([]byte(value)))
	}

	return src, nil
}

// load returns the current in-memory value.
func (s *echSource) load() []byte {
	v := s.value.Load()
	if v == nil {
		return nil
	}
	return v.([]byte)
}

// reload re-reads the file (if file-backed) and updates the atomic value.
func (s *echSource) reload() error {
	if s.filePath == "" {
		return nil // inline mode — nothing to do
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.value.Store(decodeBase64OrRaw(data))
	s.mu.Unlock()
	return nil
}

// modTime returns the file modification time, or zero if inline.
func (s *echSource) modTime() (time.Time, error) {
	if s.filePath == "" {
		return time.Time{}, nil
	}
	info, err := os.Stat(s.filePath)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// decodeBase64OrRaw tries to decode data as base64. If decoding fails,
// the raw bytes are returned as-is (for binary ECHConfig files).
func decodeBase64OrRaw(data []byte) []byte {
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return data
	}
	return decoded
}

// --- File Watcher ---

// fileWatcher periodically checks file modification times and reloads
// changed files into their associated echSource values.
type fileWatcher struct {
	sources  []*echSource
	interval time.Duration
	stopCh   chan struct{}
	lastMT   map[*echSource]time.Time
}

func newFileWatcher(sources []*echSource, interval time.Duration) *fileWatcher {
	fw := &fileWatcher{
		sources:  sources,
		interval: interval,
		stopCh:   make(chan struct{}),
		lastMT:   make(map[*echSource]time.Time),
	}
	// Initialize last known mtimes.
	for _, src := range sources {
		mt, _ := src.modTime()
		fw.lastMT[src] = mt
	}
	return fw
}

func (fw *fileWatcher) start() {
	go fw.loop()
}

func (fw *fileWatcher) stop() {
	close(fw.stopCh)
}

func (fw *fileWatcher) loop() {
	ticker := time.NewTicker(fw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-fw.stopCh:
			return
		case <-ticker.C:
			for _, src := range fw.sources {
				mt, err := src.modTime()
				if err != nil {
					continue
				}
				if !mt.After(fw.lastMT[src]) {
					continue
				}
				if err := src.reload(); err != nil {
					continue
				}
				fw.lastMT[src] = mt
			}
		}
	}
}

