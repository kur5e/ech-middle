// Package ca provides X.509 certificate authority management for MITM proxy.
// It generates a self-signed ECDSA P-256 root CA on first run, persists it
// to disk, and can dynamically sign per-host TLS certificates on demand.
// Signed certificates are cached in memory (LRU) and on disk for reuse across
// restarts, avoiding repeated signing and client certificate warnings.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// Root CA validity period.
	caValidYears = 10

	// Per-host certificate validity period.
	hostCertValidYears = 1

	// Default filenames for the CA key pair.
	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"

	// Subdirectory for cached per-host certificates.
	certsDirName = "certs"
)

// CA holds the root certificate authority used to sign per-host certificates.
type CA struct {
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	dir         string

	mu    sync.RWMutex
	cache map[string]*tls.Certificate // hostname -> signed cert (LRU managed)
	lru   []string                    // simple LRU eviction queue
}

// LoadOrGenerateCA loads an existing CA from disk, or generates a new one
// if no CA files exist in the given directory. certDir is the root CA storage
// directory (typically ~/.ech-middle/).
func LoadOrGenerateCA(certDir string) (*CA, error) {
	certPath := filepath.Join(certDir, caCertFile)
	keyPath := filepath.Join(certDir, caKeyFile)

	// Try loading existing CA first.
	if ca, err := loadCA(certPath, keyPath, certDir); err == nil {
		return ca, nil
	}

	// Generate a new root CA.
	ca, err := generateCA(certPath, keyPath, certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root CA: %w", err)
	}
	return ca, nil
}

// loadCA reads a PEM-encoded CA certificate and private key from disk.
func loadCA(certPath, keyPath, certDir string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read CA cert %q: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read CA key %q: %w", keyPath, err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CA key pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	// Ensure certs cache directory exists.
	certsDir := filepath.Join(certDir, certsDirName)
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create certs cache dir %q: %w", certsDir, err)
	}

	return &CA{
		Certificate: cert,
		Leaf:        leaf,
		dir:         certDir,
		cache:       make(map[string]*tls.Certificate),
	}, nil
}

// generateCA creates a new ECDSA P-256 root CA and writes it to disk.
func generateCA(certPath, keyPath, certDir string) (*CA, error) {
	// Generate ECDSA P-256 private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDSA key generation failed: %w", err)
	}

	// Serial number.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial generation failed: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ech-middle Root CA",
			Organization: []string{"ech-middle"},
		},
		NotBefore:             now.Add(-30 * 24 * time.Hour), // 30-day backdate for clock skew
		NotAfter:              now.Add(caValidYears * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("certificate creation failed: %w", err)
	}

	// Parse the generated certificate to get the leaf.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cannot parse generated certificate: %w", err)
	}

	// Write PEM files (restrictive permissions for private key).
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create CA dir %q: %w", certDir, err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot write %q: %w", certPath, err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot write %q: %w", keyPath, err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal private key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	// Build the tls.Certificate.
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	// Ensure certs cache directory.
	certsDir := filepath.Join(certDir, certsDirName)
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create certs cache dir %q: %w", certsDir, err)
	}

	return &CA{
		Certificate: tlsCert,
		Leaf:        leaf,
		dir:         certDir,
		cache:       make(map[string]*tls.Certificate),
	}, nil
}

// SignHost generates a TLS certificate for the given hostname signed by the
// root CA. Results are cached in memory (LRU) and persisted to disk.
func (ca *CA) SignHost(hostname string) (*tls.Certificate, error) {
	// Check memory cache first.
	ca.mu.RLock()
	cached, ok := ca.cache[hostname]
	ca.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// Check disk cache.
	cert, err := ca.loadFromDisk(hostname)
	if err == nil {
		ca.mu.Lock()
		ca.cache[hostname] = cert
		ca.mu.Unlock()
		return cert, nil
	}

	// Sign a new certificate.
	cert, err = ca.signHost(hostname)
	if err != nil {
		return nil, err
	}

	// Persist to disk cache.
	ca.saveToDisk(hostname, cert)

	// Store in memory cache with LRU eviction.
	ca.mu.Lock()
	ca.cache[hostname] = cert
	ca.lru = append(ca.lru, hostname)
	// Evict oldest entry if cache exceeds 512 entries.
	if len(ca.lru) > 512 {
		evict := ca.lru[0]
		ca.lru = ca.lru[1:]
		delete(ca.cache, evict)
	}
	ca.mu.Unlock()

	return cert, nil
}

// signHost creates a new certificate for the given hostname.
func (ca *CA) signHost(hostname string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDSA key generation failed: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial generation failed: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"ech-middle MITM"},
		},
		NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter:  now.Add(hostCertValidYears * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:              []string{hostname},
		BasicConstraintsValid: true,
	}

	caPriv := ca.Certificate.PrivateKey.(crypto.Signer)
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, fmt.Errorf("certificate signing failed: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

// loadFromDisk attempts to load a cached certificate from disk.
func (ca *CA) loadFromDisk(hostname string) (*tls.Certificate, error) {
	certPath := ca.cachedCertPath(hostname)
	keyPath := ca.cachedKeyPath(hostname)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// saveToDisk persists a signed certificate to the disk cache.
func (ca *CA) saveToDisk(hostname string, cert *tls.Certificate) {
	certPath := ca.cachedCertPath(hostname)
	keyPath := ca.cachedKeyPath(hostname)

	certOut, err := os.Create(certPath)
	if err != nil {
		return
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
}

// cachedCertPath returns the disk path for a cached host certificate.
func (ca *CA) cachedCertPath(hostname string) string {
	// Replace characters unsafe for filenames.
	safe := sanitizeHostname(hostname)
	return filepath.Join(ca.dir, certsDirName, safe+".pem")
}

// cachedKeyPath returns the disk path for a cached host private key.
func (ca *CA) cachedKeyPath(hostname string) string {
	safe := sanitizeHostname(hostname)
	return filepath.Join(ca.dir, certsDirName, safe+"-key.pem")
}

// sanitizeHostname replaces characters that are unsafe in filenames.
func sanitizeHostname(hostname string) string {
	result := make([]byte, 0, len(hostname))
	for _, c := range []byte(hostname) {
		switch {
		case c >= 'a' && c <= 'z':
			result = append(result, c)
		case c >= 'A' && c <= 'Z':
			result = append(result, c)
		case c >= '0' && c <= '9':
			result = append(result, c)
		case c == '.' || c == '-' || c == '_':
			result = append(result, c)
		case c == '*':
			result = append(result, '_', 'w', 'c') // wildcard
		default:
			result = append(result, '_')
		}
	}
	return string(result)
}

// TLSConfig returns a *tls.Config that presents a dynamically-signed
// certificate for the requested hostname during MITM TLS handshakes.
// This is intended to be used as goproxy's TLSConfig callback.
func (ca *CA) TLSConfig() func(host string) (*tls.Config, error) {
	return func(host string) (*tls.Config, error) {
		// Strip port if present.
		hostname, _, err := netJointHostPort(host)
		if err != nil {
			hostname = host
		}

		cert, err := ca.SignHost(hostname)
		if err != nil {
			return nil, fmt.Errorf("cannot sign cert for %q: %w", hostname, err)
		}

		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
}

// CAPEM returns the CA certificate in PEM-encoded form, suitable for
// serving to clients that need to trust the proxy (e.g., mobile devices).
func (ca *CA) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Leaf.Raw,
	})
}

// CADir returns the CA storage directory path.
func (ca *CA) CADir() string { return ca.dir }

// netJointHostPort is a simplified version of net.SplitHostPort.
func netJointHostPort(host string) (string, string, error) {
	// Try the standard library first.
	h, p, err := netStdSplitHostPort(host)
	if err == nil {
		return h, p, nil
	}
	// If it fails (e.g., IPv6 without brackets), assume no port.
	return host, "", nil
}

// netStdSplitHostPort delegates to the standard library.
func netStdSplitHostPort(host string) (string, string, error) {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			// Check for IPv6 bracket.
			if host[0] == '[' {
				return host[1 : i-1], host[i+1:], nil
			}
			return host[:i], host[i+1:], nil
		}
		if host[i] < '0' || host[i] > '9' {
			break
		}
	}
	return host, "", fmt.Errorf("no port")
}

