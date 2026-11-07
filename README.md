# tokmap

An asynchronous network scanner written in Rust, with its own service signatures built from recordings of real software. Optionally integrates with LLMs (Claude, OpenAI, Gemini, Ollama) for banner analysis.

**Status: work in progress.** See [Limitations](#limitations) below.

## Building

Requires Rust toolchain (tested on stable).

```
cargo build --release
```

The binaries will be at `target/release/tokmap` and `target/release/tokmap-replay`.

On Windows, linking needs `Packet.lib` from the [Npcap SDK](https://npcap.com/#download): unpack it and add its `Lib/x64` folder to the `LIB` environment variable. Running needs Npcap installed.

## Service signatures

Service probes and signatures live in [`signatures/`](signatures/) and are built into the binary:

- `tokmap.probes`: what tokmap sends. Each probe follows a public protocol specification, named beside it.
- `verified.matches`: signatures, each tested against recordings of real software, with the image digests it was tested on.

Signatures are produced by the [signature factory](factory/README.md), which runs software in Docker, records its replies, drafts signatures and checks them. Until a service has a signature, detection falls back to simple built-in parsers for SSH, HTTP, FTP and SMTP banners.

Extra signature files can be added at run time with `--signatures FILE`.

## Optional data files

Read from the working directory if present:

- `oui.csv`: MAC vendor names, from the [IEEE registry](https://standards-oui.ieee.org/oui/oui.csv)
- `nmap-services`: port frequency data for `--top-ports` and `-F`. Without it, a built-in list is used.
- `nmap-os-db`: OS fingerprints for `-O`

## Usage

```
# Basic scan
tokmap -t 192.168.1.1 -p 80,443,22

# Top 100 ports
tokmap -t 192.168.1.1 -F

# Service detection
tokmap -t 192.168.1.1 -p 80,443,22 -s

# UDP and TCP ports in one scan
tokmap -t 192.168.1.1 --udp --syn -p U:53,161,T:22,80

# CIDR range, IPv4 or IPv6
tokmap -t 192.168.1.0/24 --top-ports 20
tokmap -t fd00::/120 -p 22,80

# Path to the host
tokmap -t 192.168.1.1 -p 443 --traceroute

# Save every probe's raw reply, as evidence for building signatures
tokmap -t 127.0.0.1 -p 6379 --connect --record evidence/

# LLM-assisted banner analysis (needs ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY or OLLAMA_HOST)
tokmap -t 192.168.1.1 -p 80 -s --llm
```

### Scan types

| Flag | Type | Privileges |
|------|------|-----------|
| `--syn` / `-S` | TCP SYN (default) | Admin/root |
| `--connect` | TCP connect | None |
| `--ack` | TCP ACK | Admin/root |
| `--window` | TCP Window | Admin/root |
| `--fin` | TCP FIN | Admin/root |
| `--null` | TCP NULL | Admin/root |
| `--xmas` | TCP Xmas | Admin/root |
| `--udp` / `-U` | UDP | None |

SYN falls back to a connect scan when no raw route exists, for example to loopback. The other raw types report an error instead.

### Output formats

- Default: table to terminal
- `--json-only`: JSON to stdout (logs go to stderr)
- `-o FILE`: JSON to file
- `--xml FILE`: XML
- `--grepable FILE`: one line per host

## Architecture

```
src/
  lib.rs            -- module exports
  bin/main.rs       -- CLI entry point (clap)
  bin/tokmap-replay.rs -- matches recorded replies against signature files
  scanner.rs        -- scan orchestration
  connect.rs        -- TCP and UDP socket probing, retries, socket and rate limits
  route.rs          -- next-hop lookup, ARP and ICMP host discovery
  packet.rs         -- raw packet construction and reply parsing
  trace.rs          -- TCP traceroute
  udp.rs            -- UDP probe payloads
  service.rs        -- service detection and reply recording
  service_db/       -- signature parser and matcher
  tls.rs            -- TLS handshakes and certificate details
  os_db.rs          -- OS fingerprint matching
  target.rs         -- CIDR, IP range, hostname and reverse DNS resolution
  ports.rs          -- port selection
  discovery.rs      -- TCP host discovery
  vendors.rs        -- MAC vendor lookup
  output.rs         -- output formatters
  llm/              -- LLM clients for assisted analysis
signatures/         -- probes and verified signatures
factory/            -- the signature factory
```

## Limitations

This is an early-stage project. Known limitations:

- **The signature set is just starting.** See [Service signatures](#service-signatures).
- **Some raw features are only unit-tested.** ACK, Window, FIN, NULL and Xmas scans, traceroute, ICMP discovery, SYN through a gateway and raw IPv6 are tested on packet building and parsing, not yet on live networks.
- **OS fingerprinting is partial.** It needs a raw IPv4 route, sends 10 probe packets and scores a subset of tests.
- **Host discovery** uses ARP on the local network, ICMP echo beyond it, and TCP when raw packets are unavailable. With more than one target, hosts that answer none of these count as down. Use `-P` to scan them anyway.
- **No scripting engine.**
- **Raw socket scanning requires admin/root.** TCP connect scan (`--connect`) works without privileges.
- **LLM integration requires an API key or Ollama** and sends service banners to that provider. It is entirely optional.
- **The desktop app in `src-tauri/` is out of date** and does not build.
- **Not audited for production use.** Do not rely on this for security-critical assessments.

## Legal

Only scan networks you own or have explicit permission to scan. Unauthorized scanning may violate applicable laws.

## License

MIT
