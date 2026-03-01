# tokmap

An asynchronous network scanner written in Rust. Uses nmap's public signature databases for service detection, OS fingerprinting, and port frequency data. Optionally integrates with LLMs (Gemini) for banner analysis.

**Status: work in progress.** See [Limitations](#limitations) below.

## Building

Requires Rust toolchain (tested on stable).

```
cargo build --release
```

The binary will be at `target/release/tokmap`.

## Nmap data files

Tokmap reads the following nmap data files from the working directory at runtime:

- `nmap-service-probes` -- service signature database (~9500 signatures)
- `nmap-services` -- port frequency data (~27k entries)
- `nmap-os-db` -- OS fingerprint database (~115k lines)
- `nmap-mac-prefixes` -- MAC vendor prefixes (~49k entries)
- `nmap-rpc` -- RPC service names (~1850 entries)
- `nmap-protocols` -- IP protocol numbers (153 entries)

These files are from the [nmap project](https://github.com/nmap/nmap/) and are not included in this repository. Download them and place them in the working directory. Tokmap degrades gracefully if any are missing.

## Usage

```
# Basic scan
tokmap -t 192.168.1.1 -p 80,443,22

# Top 100 ports (frequency-ranked from nmap-services)
tokmap -t 192.168.1.1 -F

# Top N ports
tokmap -t 192.168.1.1 --top-ports 50

# Service detection (banner grabbing + nmap signature matching)
tokmap -t 192.168.1.1 -p 80,443,22 -s

# OS detection
tokmap -t 192.168.1.1 -p 80,443 -O

# CIDR range
tokmap -t 192.168.1.0/24 --top-ports 20

# IP range
tokmap -t 192.168.1.1-50 -F

# Timing templates (T0=paranoid .. T5=insane)
tokmap -t 192.168.1.1 -T4 -F

# LLM-assisted banner analysis (requires GEMINI_API_KEY env var)
tokmap -t 192.168.1.1 -p 80 -s --llm
```

### Scan types

| Flag | Type | Privileges |
|------|------|-----------|
| `--syn` / `-S` | TCP SYN (default) | Admin/root |
| `--connect` | TCP connect | None |
| `--ack` / `-A` | TCP ACK | Admin/root |
| `--window` / `-W` | TCP Window | Admin/root |
| `--fin` | TCP FIN | Admin/root |
| `--null` / `-N` | TCP NULL | Admin/root |
| `--xmas` / `-X` | TCP Xmas | Admin/root |
| `--udp` / `-U` | UDP | Admin/root |

### Output formats

- Default: nmap-style table to terminal
- `--json-only`: JSON to stdout
- `-o file.json`: JSON to file
- XML and grepable output available via library API (`OutputFormatter::write_xml`, `OutputFormatter::write_grepable`)

## Architecture

```
src/
  lib.rs            -- module exports
  bin/main.rs       -- CLI entry point (clap)
  scanner.rs        -- core scan engine (raw sockets via pnet, async via tokio)
  packet.rs         -- TCP/IP packet construction and response parsing
  udp.rs            -- UDP probes (18 protocol-specific payloads)
  service.rs        -- banner grabbing and service identification
  service_db/       -- nmap-service-probes parser and matcher
  os_db.rs          -- nmap-os-db parser
  nmap_data.rs      -- parsers for nmap-services, nmap-mac-prefixes, nmap-rpc, nmap-protocols
  target.rs         -- CIDR, IP range, hostname resolution
  timing.rs         -- timing templates (T0-T5)
  ports.rs          -- port selection (nmap frequency data with hardcoded fallback)
  discovery.rs      -- host discovery (TCP ping)
  output.rs         -- output formatters (table, JSON, XML, grepable)
  llm/              -- Gemini API client for LLM-assisted analysis
  types.rs          -- shared types
```

## Limitations

This is an early-stage project. Known limitations:

- **Service detection is passive only.** Tokmap matches banners against the nmap signature database but does not actively send nmap probe payloads. Detection accuracy is lower than nmap for services that don't send banners unprompted.
- **OS fingerprinting is simplified.** The full nmap-os-db is loaded and parsed, but matching uses only TTL and window size heuristics. Nmap's full fingerprinting suite (SEQ, OPS, WIN, ECN, T1-T7 tests) is not implemented.
- **IPv4 only.** No IPv6 support.
- **Reverse DNS is not implemented.**
- **Windows-focused development.** Tested primarily on Windows. Should work on Linux/macOS but not extensively tested.
- **No scripting engine.** Nmap's NSE equivalent does not exist.
- **Raw socket scanning requires admin/root.** TCP connect scan (`--connect`) works without privileges.
- **UDP scanning is basic.** Sends protocol-specific probes for 18 common services but lacks the full nmap UDP probe set.
- **LLM integration requires a Gemini API key** and makes external API calls. It is entirely optional.
- **Not audited for production use.** Do not rely on this for security-critical assessments.

## Legal

Only scan networks you own or have explicit permission to scan. Unauthorized scanning may violate applicable laws.

## License

MIT
