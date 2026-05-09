# ech-middle

**ECH upgrade proxy** — A cross-platform, privacy-first proxy that transparently upgrades non-ECH HTTPS traffic to Encrypted Client Hello (ECH), protecting SNI privacy for devices and software that lack native ECH support.

## Why

Your Firefox on a modern OS negotiates ECH just fine — `sni=encrypted`. But your old phone, your IoT devices, or your favorite CLI tool? They still send the target hostname in cleartext during the TLS handshake. Network observers can see exactly which sites you visit.

**ech-middle** sits between your devices and the internet. It intercepts HTTPS connections, resolves the target's ECH configuration via DNS-over-HTTPS, and re-establishes the outbound connection with ECH. Devices that can't do ECH on their own get full SNI protection — no OS upgrade required.

## Commands

```
ech-middle serve [flags]       Start the proxy
ech-middle guide               Interactive config wizard with validation
ech-middle ca                  View CA certificate info
ech-middle ca --regenerate     Replace existing CA
ech-middle ca --out DIR        Generate CA in a custom directory
```

## Features

- **ECH upgrade** — Automatic ECH negotiation for all outbound HTTPS traffic
- **Dual inbound** — HTTP proxy and SOCKS5 proxy simultaneously
- **Strict/opportunistic modes** — Block or fall back when ECH is unavailable
- **DNS-over-HTTPS** — ECH config discovery via DoH; rejects plaintext UDP to public servers
- **CF module** — Auto-detect Cloudflare-proxied sites and inject ECH config
- **ECH config injection** — Manual ECH config per domain with file hot-reload
- **CA management** — `ech-middle ca` view/regenerate; `/ca` endpoint for mobile download
- **MITM CA** — Auto-generated ECDSA P-256 root CA with per-host cert signing and disk cache
- **Access control** — IP allowlist (CIDR), HTTP Basic Auth, SOCKS5 username/password
- **Outbound interface binding** — Bind to a specific network interface (Linux, macOS)
- **Guide wizard** — `ech-middle guide` with input validation and CA setup
- **Single binary** — Statically linked, zero runtime dependencies
- **Cross-platform** — Pre-built binaries for Linux, macOS, Windows, OpenWRT

## Quick Start

### 1. Generate a config

```bash
./ech-middle guide
```

Walks through every setting with validation: ports, DNS, CA storage, access control, Cloudflare module, logging. Invalid input is rejected with a hint.

### 2. Start the proxy

```bash
./ech-middle serve
```

Or with a custom config and debug logging:

```bash
./ech-middle serve -c my-config.yaml -v
```

### 3. Install the CA certificate

Every client device must trust the proxy's CA. The CA is auto-generated on first run.

**Option A — Download via browser** (easiest for mobile):
```
http://<proxy-ip>:8080/ca
```

**Option B — View and install manually**:
```bash
ech-middle ca                    # Show CA info and file path
ech-middle ca --out /some/dir    # Generate CA in custom directory
```

| OS | Install method |
|----|---------------|
| **iOS** | Open `/ca` in Safari → install profile → Settings → General → About → Certificate Trust Settings → **Enable** |
| **Android** | Download `/ca` → Settings → Security → Install certificate → CA certificate |
| **Windows** | `certutil -addstore Root %USERPROFILE%\.ech-middle\ca.pem` |
| **macOS** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.ech-middle/ca.pem` |
| **Linux** | `sudo cp ~/.ech-middle/ca.pem /usr/local/share/ca-certificates/ech-middle.crt && sudo update-ca-certificates` |

### 4. Configure your devices

Point any device, browser, or application at the proxy:

| Protocol | Address | curl example |
|----------|---------|-------------|
| HTTP | `<proxy-ip>:8080` | `curl -x http://10.0.0.5:8080 https://tls-ech.dev` |
| SOCKS5 | `<proxy-ip>:1080` | `curl --socks5-hostname 10.0.0.5:1080 https://tls-ech.dev` |

### 5. Verify ECH is working

```bash
# Should show: "You are using ECH. :)"
curl -x http://localhost:8080 https://tls-ech.dev

# Should show: sni=encrypted
curl -x http://localhost:8080 https://blog.chaimi.cc/cdn-cgi/trace

# SOCKS5 works too
curl --socks5-hostname localhost:1080 https://tls-ech.dev
```

## Configuration

```yaml
# ech-middle.yaml
inbound:
  http:
    listen: ":8080"
  socks5:
    listen: ":1080"

access:
  ip_allow: []                    # ["192.168.1.0/24"]
  http_auth:
    enabled: false
    username: ""
    password: ""
  socks5_auth:
    enabled: false
    username: ""
    password: ""

outbound:
  interface: ""                   # eth0, en0 (Linux/macOS)
  dns:
    intranet_safe: false
    servers:
      - "https://1.1.1.1/dns-query"
      # - "system"                # requires intranet_safe: true
      # - "10.0.0.1:53"          # requires intranet_safe: true
  timeout:
    dns: 5
    tls: 10
    idle: 120

ech:
  mode: "strict"                  # strict | opportunistic
  inject: {}                      # {"example.com": "AEX+DQ...", "other.org": "@file:/data/ech.bin"}
  file_watch: 30

cf:
  enabled: false
  ech_config: ""                  # auto-discovered when empty
  auto_discover: true
  discover_from: ["crypto.cloudflare.com"]
  ip_ranges: []
  ip_prefer: []                   # ECH-mode only

runtime:
  ca_dir: ""                      # default: ~/.ech-middle/
  shutdown: "immediate"           # immediate | graceful
  shutdown_timeout: 30
  log:
    level: "info"                 # error | warn | info | debug
    file: ""                      # stdout
    color: true
```

## CLI Reference

```
ech-middle serve [flags]

Flags:
  -c, --config FILE       Config file path (default: ./ech-middle.yaml)
  --http-listen ADDR      Override inbound.http.listen
  --socks-listen ADDR     Override inbound.socks5.listen
  --dns URL               DNS server (repeatable)
  --ech-mode MODE         ECH mode: strict | opportunistic
  --log-level LEVEL       Log level: error | warn | info | debug
  --log-file FILE         Log file (default: stdout)
  -v, --verbose           Shortcut for --log-level debug
```

## ECH Modes

| Mode | No ECH available | ECH rejected |
|------|-----------------|-------------|
| **strict** (default) | Block connection | Block connection |
| **opportunistic** | Fall back to plain TLS | Fall back to plain TLS |

## Building from Source

```bash
git clone https://github.com/example/ech-middle.git
cd ech-middle
go build -ldflags="-s -w" .
```

Requires Go 1.23+.

### Cross-compile for all platforms

```bash
# Bash (Linux, macOS, Git Bash on Windows)
bash scripts/build.sh
bash scripts/build.sh -o ./release linux/amd64

# PowerShell (Windows)
.\scripts\build.ps1
.\scripts\build.ps1 -Target linux/amd64 -OutDir .\release
```

Outputs:

| Binary | Platform |
|--------|----------|
| `ech-middle_windows_amd64.exe` | Windows x64 |
| `ech-middle_linux_amd64` | Linux x64 |
| `ech-middle_linux_arm64` | Linux ARM64 |
| `ech-middle_darwin_amd64` | macOS Intel |
| `ech-middle_darwin_arm64` | macOS Apple Silicon |
| `ech-middle_openwrt_mipsle` | OpenWRT MIPS |

## How It Works

```
Device (no ECH)              ech-middle                       Target
     |                           |                                |
     |-- CONNECT example.com --> |                                |
     |                           |-- DoH query: HTTPS record ---->| DNS
     |                           |<-- ECHConfigList --------------|
     |<-- 200 OK ----------------|                                |
     |                           |                                |
     |-- TLS (plaintext SNI) --->|                                |
     |  [proxy terminates TLS]   |                                |
     |                           |-- TLS 1.3 + ECH -------------->|
     |                           |   (SNI encrypted)              |
     |-- HTTP request ---------->|-- HTTP request --------------->|
     |<-- response --------------|<-- response -------------------|
```

## Security Notes

- **CA private key** at `~/.ech-middle/ca-key.pem` must be protected (`chmod 600`)
- **Plain HTTP is rejected** — only HTTPS traffic that can be ECH-upgraded is handled
- **Proxy listener is plaintext** — credentials are cleartext on the local network; use IP allowlists or deploy on trusted networks
- **DNS queries use DoH** by default — plaintext UDP DNS to public servers is rejected at startup

## License

MIT
