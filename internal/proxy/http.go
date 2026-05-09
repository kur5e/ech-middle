package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"ech-middle/internal/auth"
	"ech-middle/internal/ca"
	"ech-middle/internal/config"
	"ech-middle/internal/echconfig"
	"ech-middle/internal/logger"
	"ech-middle/internal/tlsext"
)

// NewHTTPProxy creates an HTTP proxy server with MITM support and ECH upgrade.
func NewHTTPProxy(cfg *config.Config, caInst *ca.CA, resolver *echconfig.Resolver, acl *auth.ACL, log *logger.Logger) (*http.Server, error) {
	proxy := goproxy.NewProxyHttpServer()

	goproxy.GoproxyCa = caInst.Certificate

	strict := cfg.Strict()
	iface := cfg.OutboundInterface()
	transport := tlsext.NewECHTransport(resolver, strict, iface)
	proxy.Tr = transport

	mitmTLSConfig := func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
		hostname, _, err := netSplitHostPort(host)
		if err != nil {
			hostname = host
		}
		cert, err := caInst.SignHost(hostname)
		if err != nil {
			return nil, fmt.Errorf("cannot sign cert for %q: %w", hostname, err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS10,
		}, nil
	}

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if acl.IsIPFilterEnabled() && !acl.CheckIP(ctx.Req.RemoteAddr) {
			log.Warnf("HTTP CONNECT denied by ACL: %s → %s", ctx.Req.RemoteAddr, host)
			ctx.Resp = goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusForbidden,
				"Access denied: IP not in allowlist")
			return goproxy.RejectConnect, host
		}

		log.Infof("HTTP CONNECT %s → %s", ctx.Req.RemoteAddr, host)

		if strings.HasSuffix(host, ":443") || !strings.Contains(host, ":") {
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectMitm,
				TLSConfig: mitmTLSConfig,
			}, host
		}

		log.Debugf("HTTP tunnel (non-443): %s", host)
		return goproxy.OkConnect, host
	})

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req.URL.Scheme == "http" {
			log.Infof("HTTP plain rejected: %s → %s", req.RemoteAddr, req.URL.Host)
			return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden,
				"Plain HTTP forwarding is not supported. This proxy only handles HTTPS traffic with ECH upgrade.")
		}

		if acl.IsHTTPAuthEnabled() {
			user, pass, ok := req.BasicAuth()
			if !ok || !acl.HTTPAuth(user, pass) {
				log.Warnf("HTTP auth failed from %s", req.RemoteAddr)
				resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired,
					"Proxy authentication required")
				resp.Header.Set("Proxy-Authenticate", "Basic realm=\"ech-middle\"")
				return nil, resp
			}
		}

		log.Debugf("HTTP request: %s %s%s (from %s)", req.Method, req.URL.Host, req.URL.Path, req.RemoteAddr)
		return req, nil
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		log.Infof("HTTP %d %s", resp.StatusCode, ctx.Req.URL.Host)
		return resp
	})

	caHandler := &caServeHandler{ca: caInst, proxy: proxy}

	server := &http.Server{
		Addr:    cfg.Inbound.HTTP.Listen,
		Handler: caHandler,
	}
	return server, nil
}

// caServeHandler wraps goproxy to serve the CA cert at /ca and /ca.pem.
type caServeHandler struct {
	ca    *ca.CA
	proxy http.Handler
}

func (h *caServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca" || r.URL.Path == "/ca.pem" {
		pemBytes := h.ca.CAPEM()
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=ech-middle-ca.pem")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pemBytes)))
		w.WriteHeader(http.StatusOK)
		w.Write(pemBytes)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func netSplitHostPort(host string) (string, string, error) {
	h, p, err := splitHostPort(host)
	if err == nil {
		return h, p, nil
	}
	return host, "", nil
}

func splitHostPort(host string) (string, string, error) {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			if host[0] == '[' {
				return host[1 : i-1], host[i+1:], nil
			}
			return host[:i], host[i+1:], nil
		}
		if host[i] < '0' || host[i] > '9' {
			break
		}
	}
	return host, "", fmt.Errorf("no port found")
}
