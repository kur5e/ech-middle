// ech-middle is a cross-platform proxy that upgrades non-ECH (Encrypted
// Client Hello) traffic to ECH, protecting SNI privacy for devices and
// software that do not natively support ECH.
//
// It supports both HTTP and SOCKS5 inbound protocols, uses DNS-over-HTTPS
// for ECH configuration discovery, and provides optional Cloudflare-specific
// ECH injection for CF-proxied websites.
//
// Usage:
//
//	ech-middle serve [flags]
//	ech-middle guide
//	ech-middle ca [--regenerate] [--out DIR]
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"runtime"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
	"golang.org/x/sync/errgroup"

	"ech-middle/internal/auth"
	"ech-middle/internal/ca"
	"ech-middle/internal/cfmod"
	"ech-middle/internal/config"
	"ech-middle/internal/echconfig"
	"ech-middle/internal/logger"
	"ech-middle/internal/proxy"
)

type serveFlags struct {
	ConfigPath  string
	HTTPListen  string
	SOCKSListen string
	DNS         []string
	ECHMode     string
	LogLevel    string
	LogFile     string
	Verbose     bool
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "guide":
		cmdGuide()
	case "ca":
		cmdCA()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ech-middle - ECH upgrade proxy

Usage:
  ech-middle serve [flags]                Start the proxy
  ech-middle guide                        Interactive config wizard
  ech-middle ca [--regenerate] [--out DIR]  CA certificate management

Serve Flags:
  -c, --config FILE        Config file path (default: ./ech-middle.yaml)
  --http-listen ADDR       Override inbound.http.listen
  --socks-listen ADDR      Override inbound.socks5.listen
  --dns URL                DNS server (repeatable)
  --ech-mode MODE          ECH mode: strict | opportunistic
  --log-level LEVEL        Log level: error | warn | info | debug
  --log-file FILE          Log file (default: stdout)
  -v, --verbose            Shortcut for --log-level debug
`)
}

func cmdServe(args []string) {
	flags := parseServeFlags(args)

	cfg, err := config.LoadConfig(flags.ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	cfg.ApplyCLI(config.CLIOverrides{
		HTTPListen:  flags.HTTPListen,
		SOCKSListen: flags.SOCKSListen,
		DNS:         flags.DNS,
		ECHMode:     flags.ECHMode,
		LogLevel:    flags.LogLevel,
		LogFile:     flags.LogFile,
		Verbose:     flags.Verbose,
	})

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	log := logger.NewLogger(cfg.Runtime.Log)
	log.Infof("ech-middle starting (mode=%s)", cfg.ECH.Mode)

	caDir := cfg.Runtime.CADir
	if caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Errorf("Cannot determine home directory: %v", err)
			os.Exit(1)
		}
		caDir = filepath.Join(home, ".ech-middle")
	}

	caInst, err := ca.LoadOrGenerateCA(caDir)
	if err != nil {
		log.Errorf("Failed to initialize CA: %v", err)
		os.Exit(1)
	}
	log.Infof("CA loaded from %s", caDir)

	acl := auth.NewACL(cfg.Access)
	if acl.IsIPFilterEnabled() || acl.IsHTTPAuthEnabled() {
		log.Infof("Access control enabled")
	}

	var cfProvider echconfig.ECHProvider
	if cfg.CF.Enabled {
		cfMod, err := cfmod.New(cfg.CF)
		if err != nil {
			log.Errorf("Failed to initialize CF module: %v", err)
			os.Exit(1)
		}
		if cfMod != nil {
			cfProvider = cfMod
		}
	}

	resolver, err := echconfig.NewResolver(cfg.Outbound.DNS, cfg.ECH, cfProvider)
	if err != nil {
		log.Errorf("Failed to initialize ECH resolver: %v", err)
		os.Exit(1)
	}
	defer resolver.Shutdown()
	log.Infof("ECH resolver initialized with %d DNS server(s)", len(cfg.Outbound.DNS.Servers))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	g, ctx := errgroup.WithContext(ctx)

	httpServer, err := proxy.NewHTTPProxy(cfg, caInst, resolver, acl, log)
	if err != nil {
		log.Errorf("Failed to create HTTP proxy: %v", err)
		os.Exit(1)
	}
	g.Go(func() error {
		log.Infof("HTTP proxy listening on %s", cfg.Inbound.HTTP.Listen)
		ln, err := net.Listen("tcp", cfg.Inbound.HTTP.Listen)
		if err != nil {
			return fmt.Errorf("HTTP proxy listen failed: %w", err)
		}
		go func() { <-ctx.Done(); ln.Close() }()
		return httpServer.Serve(ln)
	})

	socksServer, err := proxy.NewSOCKS5Proxy(cfg, caInst, resolver, acl, log)
	if err != nil {
		log.Errorf("Failed to create SOCKS5 proxy: %v", err)
		os.Exit(1)
	}
	g.Go(func() error {
		log.Infof("SOCKS5 proxy listening on %s", cfg.Inbound.SOCKS5.Listen)
		ln, err := net.Listen("tcp", cfg.Inbound.SOCKS5.Listen)
		if err != nil {
			return fmt.Errorf("SOCKS5 proxy listen failed: %w", err)
		}
		go func() { <-ctx.Done(); ln.Close() }()
		return socksServer.Serve(ln)
	})

	go func() {
		select {
		case sig := <-sigCh:
			log.Infof("Received signal %v, shutting down...", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := g.Wait(); err != nil {
		log.Errorf("Server error: %v", err)
	}
	log.Infof("ech-middle stopped")
}

func parseServeFlags(args []string) serveFlags {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	f := serveFlags{}
	fs.StringVar(&f.ConfigPath, "c", config.DefaultConfigFilePath, "")
	fs.StringVar(&f.ConfigPath, "config", config.DefaultConfigFilePath, "Config file path")
	fs.StringVar(&f.HTTPListen, "http-listen", "", "Override inbound.http.listen")
	fs.StringVar(&f.SOCKSListen, "socks-listen", "", "Override inbound.socks5.listen")
	fs.Func("dns", "DNS server URL (repeatable)", func(s string) error { f.DNS = append(f.DNS, s); return nil })
	fs.StringVar(&f.ECHMode, "ech-mode", "", "ECH mode: strict | opportunistic")
	fs.StringVar(&f.LogLevel, "log-level", "", "Log level: error | warn | info | debug")
	fs.StringVar(&f.LogFile, "log-file", "", "Log file path (default: stdout)")
	fs.BoolVar(&f.Verbose, "v", false, "Shortcut for --log-level debug")
	fs.BoolVar(&f.Verbose, "verbose", false, "Shortcut for --log-level debug")
	fs.Parse(args)
	return f
}

// --- guide command ---

func cmdGuide() {
	fmt.Println("+----------------------------------------------+")
	fmt.Println("|     ech-middle Configuration Generator       |")
	fmt.Println("+----------------------------------------------+")
	fmt.Println()
	fmt.Println("This wizard helps you create an ech-middle.yaml config file.")
	fmt.Println("Press Enter to accept the default shown in [brackets].")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	cfg := config.DefaultConfig()

	// -- Inbound --
	fmt.Println("--- Inbound Listeners ---")
	cfg.Inbound.HTTP.Listen = prompt(reader, "HTTP proxy listen address", cfg.Inbound.HTTP.Listen)
	cfg.Inbound.SOCKS5.Listen = prompt(reader, "SOCKS5 proxy listen address", cfg.Inbound.SOCKS5.Listen)

	// -- DNS --
	fmt.Println("\n--- DNS Configuration ---")
	dnsInput := prompt(reader, "DNS server (DoH URL, 'system', or IP:53)",
		"https://v.recipes/dns/cloudflare-dns.com/dns-query")
	cfg.Outbound.DNS.Servers = []string{dnsInput}

	intranetInput := prompt(reader, "Enable intranet-safe mode? (true/false)", "false")
	for !isBool(intranetInput) {
		fmt.Println("  Please enter true or false.")
		intranetInput = prompt(reader, "Enable intranet-safe mode? (true/false)", "false")
	}
	cfg.Outbound.DNS.IntranetSafe = intranetInput == "true" || intranetInput == "yes"

	// Outbound interface binding (Linux/macOS only).
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fmt.Println("\n--- Outbound Interface ---")
		fmt.Println("  Bind all outbound connections to a specific network interface.")
		fmt.Println("  Leave empty for system default routing.")
		ifaceInput := prompt(reader, "Network interface name (e.g. eth0, en0)", "")
		if ifaceInput != "" {
			cfg.Outbound.Interface = ifaceInput
			fmt.Printf("  Outbound traffic will use interface: %s\n", ifaceInput)
		}
	}

	// -- ECH --
	fmt.Println("\n--- ECH Settings ---")
	cfg.ECH.Mode = promptValid(reader, "ECH mode (strict or opportunistic)", cfg.ECH.Mode,
		func(v string) bool { return v == "strict" || v == "opportunistic" },
		"must be 'strict' or 'opportunistic'")

	// -- CA Certificate --
	fmt.Println("\n--- CA Certificate ---")
	fmt.Println("  The proxy uses a root CA to perform HTTPS interception (MITM).")
	fmt.Println("  Client devices must install this CA to trust the proxy.")
	caInput := prompt(reader, "CA storage directory (empty = default ~/.ech-middle/)", "")
	if caInput != "" {
		cfg.Runtime.CADir = caInput
	}
	fmt.Println("  Generating CA if needed...")
	certDir := cfg.Runtime.CADir
	if certDir == "" {
		home, _ := os.UserHomeDir()
		certDir = filepath.Join(home, ".ech-middle")
	}
	if ci, err := ca.LoadOrGenerateCA(certDir); err != nil {
		fmt.Printf("  CA setup failed: %v\n", err)
	} else {
		fp := fmt.Sprintf("%X", sha256.Sum256(ci.Leaf.Raw))
		fmt.Printf("  CA ready. Fingerprint: %s\n", fp)
		fmt.Println("  Download at: http://<proxy-ip>:<port>/ca")
	}

	// -- Access Control --
	fmt.Println("\n--- Access Control ---")
	ipAllow := prompt(reader, "IP allowlist CIDRs (comma-separated, empty=none)", "")
	if ipAllow != "" {
		for _, cidr := range strings.Split(ipAllow, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				cfg.Access.IPAllow = append(cfg.Access.IPAllow, cidr)
			}
		}
	}

	httpAuth := prompt(reader, "Enable HTTP Basic Auth? (true/false)", "false")
	for !isBool(httpAuth) {
		fmt.Println("  Please enter true or false.")
		httpAuth = prompt(reader, "Enable HTTP Basic Auth? (true/false)", "false")
	}
	if httpAuth == "true" || httpAuth == "yes" {
		cfg.Access.HTTPAuth.Enabled = true
		cfg.Access.HTTPAuth.Username = prompt(reader, "  HTTP Auth username", "proxy")
		cfg.Access.HTTPAuth.Password = prompt(reader, "  HTTP Auth password", "")
	}

	socksAuth := prompt(reader, "Enable SOCKS5 username/password auth? (true/false)", "false")
	for !isBool(socksAuth) {
		fmt.Println("  Please enter true or false.")
		socksAuth = prompt(reader, "Enable SOCKS5 username/password auth? (true/false)", "false")
	}
	if socksAuth == "true" || socksAuth == "yes" {
		cfg.Access.SOCKS5Auth.Enabled = true
		cfg.Access.SOCKS5Auth.Username = prompt(reader, "  SOCKS5 Auth username", "proxy")
		cfg.Access.SOCKS5Auth.Password = prompt(reader, "  SOCKS5 Auth password", "")
	}

	// -- CF Module --
	fmt.Println("\n--- Cloudflare Module ---")
	cfEnabled := prompt(reader, "Enable CF ECH injection? (true/false)", "false")
	for !isBool(cfEnabled) {
		fmt.Println("  Please enter true or false.")
		cfEnabled = prompt(reader, "Enable CF ECH injection? (true/false)", "false")
	}
	if cfEnabled == "true" || cfEnabled == "yes" {
		cfg.CF.Enabled = true
		cfg.CF.AutoDiscover = true
		fmt.Println("  CF module enabled with auto-discovery from crypto.cloudflare.com")
	}

	// -- Runtime --
	fmt.Println("\n--- Runtime ---")
	cfg.Runtime.Log.Level = promptValid(reader, "Log level (error/warn/info/debug)", cfg.Runtime.Log.Level,
		func(v string) bool {
			switch v {
			case "error", "warn", "info", "debug":
				return true
			}
			return false
		}, "must be: error, warn, info, debug")
	logFile := prompt(reader, "Log file path (empty=stdout)", "")
	cfg.Runtime.Log.File = logFile

	outputPath := prompt(reader, "\nSave config to", "ech-middle.yaml")

	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal config: %v\n", err)
		os.Exit(1)
	}
	header := "# ech-middle configuration\n# Generated by: ech-middle guide\n\n"
	full := header + string(data)
	if err := os.WriteFile(outputPath, []byte(full), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nConfiguration saved to %s\n", outputPath)
	fmt.Println("Start the proxy with: ech-middle serve -c " + outputPath)
}

// --- ca command ---

func cmdCA() {
	regenerate := false
	outDir := ""
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--regenerate", "-r":
			regenerate = true
		case "--out", "-o":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		}
	}

	caDir := outDir
	if caDir == "" {
		if cfg, err := config.LoadConfig(""); err == nil {
			caDir = cfg.Runtime.CADir
		}
	}
	if caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot determine home directory: %v\n", err)
			os.Exit(1)
		}
		caDir = filepath.Join(home, ".ech-middle")
	}

	if regenerate {
		fmt.Printf("Regenerating CA in %s ...\n", caDir)
		os.Remove(filepath.Join(caDir, "ca.pem"))
		os.Remove(filepath.Join(caDir, "ca-key.pem"))
	}

	caInst, err := ca.LoadOrGenerateCA(caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA error: %v\n", err)
		os.Exit(1)
	}

	leaf := caInst.Leaf
	fp := sha256.Sum256(leaf.Raw)

	fmt.Printf("CA Directory:  %s\n", caDir)
	fmt.Printf("Subject:       %s\n", leaf.Subject.CommonName)
	fmt.Printf("Valid Until:   %s\n", leaf.NotAfter.Format("2006-01-02"))
	fmt.Printf("Fingerprint:   %X\n", fp)
	fmt.Printf("Key Type:      %s\n", leaf.PublicKeyAlgorithm.String())
	fmt.Println()
	fmt.Println("Install this CA on client devices to trust the proxy:")
	fmt.Println("  http://<proxy-ip>:<port>/ca")
	fmt.Println()
	fmt.Printf("File location: %s\n", filepath.Join(caDir, "ca.pem"))
}

// --- helpers ---

func prompt(reader *bufio.Reader, question, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", question, defaultVal)
	} else {
		fmt.Printf("%s: ", question)
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultVal
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

func promptValid(reader *bufio.Reader, q, def string, ok func(string) bool, hint string) string {
	for {
		v := prompt(reader, q, def)
		if v == def || ok(v) {
			return v
		}
		fmt.Printf("  Invalid: %s\n", hint)
	}
}

func isBool(s string) bool {
	return s == "true" || s == "false" || s == "yes" || s == "no"
}
