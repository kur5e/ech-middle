// Package tlsext provides an ECH-enabled TLS dialer with support for
// retry on ECH rejection, concurrent multi-IP (Happy Eyeballs) dialing,
// preferred IP injection from ECH providers, and network interface binding.
package tlsext

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"ech-middle/internal/echconfig"
)

// DialECH establishes a TLS connection to the target, using ECH when
// the provided result contains an ECHConfig. It handles ECHRejectionError
// by updating the resolver cache and retrying once.
//
// Parameters:
//   - result: ECH resolution result (may have nil Config for plain TLS fallback)
//   - strict: if true, non-ECH connections are rejected
//   - iface: network interface name for socket binding (empty = system default)
//   - onRetry: called with the retry config list from an ECH rejection
func DialECH(ctx context.Context, network, addr string,
	result *echconfig.ECHResult, strict bool, iface string, onRetry func([]byte)) (*tls.Conn, error) {
	if result == nil || result.Config == nil {
		if strict {
			return nil, fmt.Errorf("ECH required but no config available for %s", addr)
		}
		return dialPlainTLS(ctx, network, addr, iface)
	}

	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		hostname = addr
	}

	dialIPs := result.PreferIPs
	usePreferred := len(dialIPs) > 0

	tlsCfg := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     hostname,
		EncryptedClientHelloConfigList: result.Config,
	}

	// First attempt.
	conn, err := dialTLSWithIPs(ctx, network, addr, dialIPs, tlsCfg, iface)
	if err == nil {
		return conn, nil
	}

	// Check if this was an ECH rejection with retry config.
	var echErr *tls.ECHRejectionError
	if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
		if onRetry != nil {
			onRetry(echErr.RetryConfigList)
		}
		tlsCfg.EncryptedClientHelloConfigList = echErr.RetryConfigList
		conn, retryErr := dialTLSWithIPs(ctx, network, addr, dialIPs, tlsCfg, iface)
		if retryErr == nil {
			return conn, nil
		}
		err = retryErr
	}

	if strict {
		return nil, fmt.Errorf("ECH connection failed: %w", err)
	}

	// Opportunistic: fall back to plain TLS.
	if usePreferred {
		plainCfg := &tls.Config{
			MinVersion: tls.VersionTLS10,
			ServerName: hostname,
		}
		return dialTLSWithIPs(ctx, network, addr, nil, plainCfg, iface)
	}

	plainCfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		ServerName: hostname,
	}
	return dialTLSWithIPs(ctx, network, addr, nil, plainCfg, iface)
}

// dialPlainTLS establishes a plain TLS connection without ECH.
func dialPlainTLS(ctx context.Context, network, addr, iface string) (*tls.Conn, error) {
	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		hostname = addr
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		ServerName: hostname,
	}

	return dialTLSWithIPs(ctx, network, addr, nil, tlsCfg, iface)
}

// dialTLSWithIPs attempts to establish a TLS connection. If preferIPs is
// non-empty, those IPs are tried first. Otherwise, the addr is resolved
// and all resolved IPs are attempted concurrently (Happy Eyeballs).
func dialTLSWithIPs(ctx context.Context, network, addr string, preferIPs []net.IP, tlsCfg *tls.Config, iface string) (*tls.Conn, error) {
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		hostname = addr
		port = "443"
	}

	if len(preferIPs) > 0 {
		for _, ip := range preferIPs {
			target := net.JoinHostPort(ip.String(), port)
			conn, err := dialOneTLS(ctx, network, target, tlsCfg, iface)
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("all preferred IPs failed for %s", hostname)
	}

	ips, err := resolveIPs(ctx, hostname)
	if err != nil || len(ips) == 0 {
		rawConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("dial failed for %s: %w", addr, err)
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake failed for %s: %w", addr, err)
		}
		return tlsConn, nil
	}

	return dialConcurrentTLS(ctx, network, port, ips, tlsCfg, iface)
}

// dialOneTLS dials a single address and performs a TLS handshake.
// If iface is non-empty, the socket is bound to that network interface
// before connecting.
func dialOneTLS(ctx context.Context, network, addr string, tlsCfg *tls.Config, iface string) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	if iface != "" {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := BindToInterface(fd, network, iface); err != nil {
					panic(err) // Binding failure is fatal; DialContext will return this
				}
			})
		}
	}

	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// dialConcurrentTLS races connections to multiple IPs and returns the first
// successful one, cancelling all others.
func dialConcurrentTLS(ctx context.Context, network, port string, ips []net.IP, tlsCfg *tls.Config, iface string) (*tls.Conn, error) {
	type result struct {
		conn *tls.Conn
		err  error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(ips))
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			addr := net.JoinHostPort(ip.String(), port)
			conn, err := dialOneTLS(ctx, network, addr, tlsCfg, iface)
			select {
			case ch <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var lastErr error
	for r := range ch {
		if r.err == nil {
			cancel()
			return r.conn, nil
		}
		lastErr = r.err
	}

	return nil, fmt.Errorf("all %d IPs failed (last error: %w)", len(ips), lastErr)
}

// resolveIPs resolves A/AAAA records for a hostname.
func resolveIPs(ctx context.Context, hostname string) ([]net.IP, error) {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}

	result := make([]net.IP, len(ips))
	for i, ip := range ips {
		result[i] = ip.IP
	}
	return result, nil
}

// NewECHTransport creates an *http.Transport that uses ECH for all outbound
// TLS connections. The transport is configured with sensible defaults for
// connection pooling and concurrency.
//
// Parameters:
//   - resolver: ECH config resolver (used by DialTLSContext to fetch ECHConfig)
//   - strict: if true, connections without ECH are rejected
//   - iface: network interface to bind outbound connections (empty = system default)
func NewECHTransport(resolver *echconfig.Resolver, strict bool, iface string) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		hostname, _, err := net.SplitHostPort(addr)
		if err != nil {
			hostname = addr
		}

		result, err := resolver.GetECHConfig(ctx, hostname)
		if err != nil {
			if strict {
				return nil, fmt.Errorf("ECH required but resolution failed for %s: %w", hostname, err)
			}
			result = &echconfig.ECHResult{}
		}

		conn, err := DialECH(ctx, network, addr, result, strict, iface, func(retryConfig []byte) {
			resolver.HandleRetry(hostname, retryConfig)
		})
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	return transport
}
