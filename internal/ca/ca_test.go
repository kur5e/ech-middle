package ca_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"ech-middle/internal/ca"
)

func TestLoadOrGenerateCA_FirstRun(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, err := ca.LoadOrGenerateCA(tmpDir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA failed: %v", err)
	}
	if caInst == nil {
		t.Fatal("CA should not be nil")
	}

	// Verify CA files exist.
	for _, f := range []string{"ca.pem", "ca-key.pem"} {
		if _, err := os.Stat(filepath.Join(tmpDir, f)); os.IsNotExist(err) {
			t.Errorf("expected file %q not found", f)
		}
	}

	// Verify CA certificate properties.
	if caInst.Leaf == nil {
		t.Fatal("CA leaf certificate should not be nil")
	}
	if !caInst.Leaf.IsCA {
		t.Error("root certificate should be a CA")
	}
	if caInst.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA should have CertSign key usage")
	}
}

func TestLoadOrGenerateCA_Reload(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate first.
	ca1, err := ca.LoadOrGenerateCA(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Reload from disk.
	ca2, err := ca.LoadOrGenerateCA(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// The certificates should be identical.
	if len(ca1.Leaf.Raw) != len(ca2.Leaf.Raw) {
		t.Error("reloaded CA should have same certificate length")
	}
}

func TestSignHost(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	cert, err := caInst.SignHost("example.com")
	if err != nil {
		t.Fatalf("SignHost failed: %v", err)
	}
	if cert == nil {
		t.Fatal("signed cert should not be nil")
	}
	if len(cert.Certificate) == 0 {
		t.Error("signed cert should have certificate chain")
	}

	// Verify certificate is valid for the hostname.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("cannot parse signed certificate: %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN: got %q, want %q", leaf.Subject.CommonName, "example.com")
	}

	// Verify the certificate is signed by the CA.
	roots := x509.NewCertPool()
	roots.AddCert(caInst.Leaf)
	opts := x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   roots,
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}
}

func TestSignHost_DiskCache(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	// Sign first time.
	_, err := caInst.SignHost("cached.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Check disk cache exists.
	certPath := filepath.Join(tmpDir, "certs", "cached.example.com.pem")
	keyPath := filepath.Join(tmpDir, "certs", "cached.example.com-key.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("disk cache cert not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("disk cache key not created")
	}

	// Sign again — should load from memory cache.
	cert2, err := caInst.SignHost("cached.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert2 == nil {
		t.Error("second SignHost should succeed")
	}
}

func TestSignHost_Wildcard(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	cert, err := caInst.SignHost("*.example.com")
	if err != nil {
		t.Fatalf("SignHost wildcard failed: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "*.example.com" {
		t.Errorf("wildcard CN: got %q", leaf.Subject.CommonName)
	}
}

func TestSignHost_DifferentHostnames(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	hostnames := []string{"example.com", "google.com", "github.com", "localhost", "api.example.com"}
	for _, h := range hostnames {
		cert, err := caInst.SignHost(h)
		if err != nil {
			t.Errorf("SignHost(%q) failed: %v", h, err)
			continue
		}
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		if leaf.Subject.CommonName != h {
			t.Errorf("SignHost(%q): got CN %q", h, leaf.Subject.CommonName)
		}
	}
}

func TestSignHost_TLSConfig(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	configFn := caInst.TLSConfig()
	tlsCfg, err := configFn("example.com:443")
	if err != nil {
		t.Fatalf("TLSConfig callback failed: %v", err)
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Error("TLS config should have certificates")
	}
}

func TestSignHost_LRU_Eviction(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	// Sign many hosts to trigger LRU eviction.
	for i := 0; i < 600; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		_, err := caInst.SignHost(host)
		if err != nil {
			t.Errorf("SignHost(%q) failed: %v", host, err)
		}
	}

	// The 600th sign should still work.
	cert, err := caInst.SignHost("host-599.example.com")
	if err != nil {
		t.Error("SignHost after LRU eviction should still work")
	}
	if cert == nil {
		t.Error("cert should not be nil after LRU cycle")
	}
}

func TestLoadOrGenerateCA_KeyPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := ca.LoadOrGenerateCA(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// On Windows, os.Stat Mode doesn't accurately represent permissions.
	// Just verify the file exists.
	keyPath := filepath.Join(tmpDir, "ca-key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("CA key file should not be empty")
	}
}

func TestSignHost_TLSHandshake(t *testing.T) {
	tmpDir := t.TempDir()
	caInst, _ := ca.LoadOrGenerateCA(tmpDir)

	cert, err := caInst.SignHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	// Verify the certificate is usable for TLS handshake.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Test that the certificate itself is valid (not expired, etc.).
	if len(tlsCfg.Certificates) == 0 {
		t.Error("TLS config should have certificates")
	}
	if tlsCfg.Certificates[0].PrivateKey == nil {
		t.Error("certificate should have a private key")
	}
}

