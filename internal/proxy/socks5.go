package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"ech-middle/internal/auth"
	"ech-middle/internal/ca"
	"ech-middle/internal/config"
	"ech-middle/internal/echconfig"
	"ech-middle/internal/logger"
	"ech-middle/internal/tlsext"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version    = 0x05
	socks5CmdConnect = 0x01
	socks5NoAuth     = 0x00
	socks5UserPass   = 0x02
	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04
	socks5RepSuccess = 0x00
	socks5RepFail    = 0x01
)

// NewSOCKS5Proxy creates a SOCKS5 proxy server with MITM support for
// TLS connections on port 443, enabling ECH upgrade. This uses a minimal
// custom SOCKS5 handler (~70 lines) that gives full control over the
// connection lifecycle — no external library buffering conflicts.
func NewSOCKS5Proxy(cfg *config.Config, caInst *ca.CA, resolver *echconfig.Resolver, acl *auth.ACL, log *logger.Logger) (*Server, error) {
	strict := cfg.Strict()
	iface := cfg.OutboundInterface()
	transport := tlsext.NewECHTransport(resolver, strict, iface)

	return &Server{
		addr:      cfg.Inbound.SOCKS5.Listen,
		transport: transport,
		ca:        caInst,
		acl:       acl,
		auth:      cfg.Access.SOCKS5Auth,
		log:       log,
	}, nil
}

// Server is a minimal SOCKS5 proxy server that handles only CONNECT
// commands with optional MITM for TLS connections on port 443.
type Server struct {
	addr      string
	transport *http.Transport
	ca        *ca.CA
	acl       *auth.ACL
	auth      config.AuthConfig
	log       *logger.Logger
}

// Serve starts the SOCKS5 proxy listener and blocks until the listener
// returns an error.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("SOCKS5 accept: %w", err)
		}
		go func() {
			defer conn.Close()
			if err := s.handleConn(conn); err != nil {
				s.log.Warnf("SOCKS5 connection error: %v", err)
			}
		}()
	}
}

// handleConn processes a single SOCKS5 client connection through all
// protocol phases: greeting, authentication, CONNECT request, and
// data relay (MITM or tunnel).
func (s *Server) handleConn(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Phase 1: greeting — read version and supported methods.
	ver, err := reader.ReadByte()
	if err != nil || ver != socks5Version {
		return fmt.Errorf("invalid SOCKS5 version: %d", ver)
	}
	nMethods, _ := reader.ReadByte()
	methods := make([]byte, nMethods)
	io.ReadFull(reader, methods)

	// Phase 1b: authenticate if required, otherwise select no-auth.
	if s.auth.Enabled {
		conn.Write([]byte{socks5Version, socks5UserPass})
		subVer, _ := reader.ReadByte()
		if subVer != 1 {
			return fmt.Errorf("invalid user/pass version: %d", subVer)
		}
		userLen, _ := reader.ReadByte()
		user := make([]byte, userLen)
		io.ReadFull(reader, user)
		passLen, _ := reader.ReadByte()
		pass := make([]byte, passLen)
		io.ReadFull(reader, pass)

		if string(user) != s.auth.Username || string(pass) != s.auth.Password {
			conn.Write([]byte{1, 1})
			return fmt.Errorf("SOCKS5 auth failed for user %q", string(user))
		}
		conn.Write([]byte{1, 0})
	} else {
		conn.Write([]byte{socks5Version, socks5NoAuth})
	}

	// Phase 2: CONNECT request.
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("read CONNECT header: %w", err)
	}
	if header[1] != socks5CmdConnect {
		return fmt.Errorf("unsupported SOCKS5 command: %d", header[1])
	}

	var hostname string
	var port uint16

	switch header[3] {
	case socks5AddrIPv4:
		ip := make([]byte, 4)
		io.ReadFull(reader, ip)
		hostname = net.IP(ip).String()
	case socks5AddrDomain:
		lenByte, _ := reader.ReadByte()
		host := make([]byte, lenByte)
		io.ReadFull(reader, host)
		hostname = string(host)
	case socks5AddrIPv6:
		ip := make([]byte, 16)
		io.ReadFull(reader, ip)
		hostname = net.IP(ip).String()
	default:
		return fmt.Errorf("unsupported address type: %d", header[3])
	}

	portBytes := make([]byte, 2)
	io.ReadFull(reader, portBytes)
	port = binary.BigEndian.Uint16(portBytes)

	addr := net.JoinHostPort(hostname, fmt.Sprint(port))

	// IP allowlist check.
	if s.acl.IsIPFilterEnabled() {
		if !s.acl.CheckIP(conn.RemoteAddr().String()) {
			conn.Write([]byte{socks5Version, socks5RepFail, 0,
				socks5AddrIPv4, 0, 0, 0, 0, 0, 0})
			return fmt.Errorf("SOCKS5: access denied for %s", conn.RemoteAddr())
		}
	}

	// Phase 3: success reply.
	conn.Write([]byte{socks5Version, socks5RepSuccess, 0,
		socks5AddrIPv4, 0, 0, 0, 0, 0, 0})

	// Phase 4: MITM for port 443, transparent tunnel otherwise.
	if port == 443 {
		s.log.Infof("SOCKS5 CONNECT %s → %s", conn.RemoteAddr(), hostname)
		return s.handleMITM(conn, reader, hostname)
	}
	return handleTunnel(conn, reader, addr)
}

// handleMITM terminates the client TLS, decrypts it, and forwards
// HTTP requests through the ECH-enabled transport.
func (s *Server) handleMITM(rawConn net.Conn, reader *bufio.Reader, hostname string) error {
	cert, err := s.ca.SignHost(hostname)
	if err != nil {
		return fmt.Errorf("MITM: cannot sign cert for %q: %w", hostname, err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS10,
	}

	// Use a connection that reads from our bufio.Reader (which may
	// have buffered the TLS ClientHello during protocol parsing) and
	// writes to the raw TCP conn.
	mitmConn := &bufferedConn{Conn: rawConn, reader: reader}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tlsConn := tls.Server(mitmConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("MITM: TLS handshake with client failed: %w", err)
	}
	defer tlsConn.Close()

	s.log.Debugf("SOCKS5 TLS handshake OK: %s", hostname)

	bufReader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("MITM: read request: %w", err)
		}

		req.URL.Scheme = "https"
		req.URL.Host = hostname
		req.RequestURI = ""

		resp, err := s.transport.RoundTrip(req)
		if err != nil {
			s.log.Warnf("SOCKS5 upstream failed for %s: %v", hostname, err)
			errBody := err.Error()
			errResp := &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Body:          io.NopCloser(strings.NewReader(errBody)),
				ContentLength: int64(len(errBody)),
			}
			errResp.Write(tlsConn)
			return nil
		}

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			return fmt.Errorf("MITM: write response: %w", err)
		}
		resp.Body.Close()
	}
}

// handleTunnel transparently forwards TCP traffic between client and target.
func handleTunnel(rawConn net.Conn, reader *bufio.Reader, addr string) error {
	targetConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("tunnel: dial %s: %w", addr, err)
	}
	defer targetConn.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, reader)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(rawConn, targetConn)
		errCh <- err
	}()
	<-errCh
	return nil
}

// bufferedConn wraps a net.Conn with a custom reader, bridging the gap
// between bufio.Reader (used for SOCKS5 protocol parsing) and TLS
// handshake. Reads go through the custom reader; writes go to the raw conn.
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

// Read overrides the embedded net.Conn.Read.
func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
