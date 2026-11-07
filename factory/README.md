# Signature factory

Builds tokmap's service signatures from recordings of real software, and proves each one before it is used.

For each image in `images.json`, every listed tag is run in Docker, every probe's reply is recorded, and a signature is drafted from what all the versions have in common. A signature is accepted only if it names every recorded version correctly and matches no other image.

## Requirements

- Docker
- Python 3.9 or later, no extra packages
- `cargo build --release` first, for `tokmap` and `tokmap-replay`

## Steps

Run from the repository root. Every command takes `--only IMAGE[,IMAGE]`.

```
python factory/factory.py capture   # run each image tag, record replies to factory/evidence/
python factory/factory.py draft     # write candidate signatures to factory/drafts/
python factory/factory.py verify    # check drafts against all evidence
python factory/factory.py accept    # verify, then add to signatures/verified.matches
python factory/factory.py score     # product and version accuracy over all evidence
```

Rebuild tokmap after `accept`, so the new signatures are built in.

`accept` holds back a signature whose pattern does not contain the product name, since it could match another product shaped the same way. Read it, and the replies it matches, then run `accept --reviewed`. Reject patterns that are generic (a bare `"version"` field, a common header) or that carry a date, a length or a counter.

`capture` skips tags that already have evidence. Use `--force` to record again, and `--prune` to delete each image after recording it.

## Adding an image

Add an entry to `images.json`:

```json
{"image": "postgres", "service": "postgresql", "product": "PostgreSQL", "tags": ["17.2", "16.6"],
 "env": {"POSTGRES_PASSWORD": "tokmap"}, "settle": 10}
```

| Field | Meaning |
|---|---|
| `image` | Docker Hub image name |
| `service` | Service name in signatures, such as `http` |
| `product` | Product name the signature reports |
| `tags` | Versions to record. The tag is taken as the version |
| `versions` | Optional `{tag: version}` when a tag is not the version |
| `env`, `args` | Optional settings the container needs to start |
| `settle` | Optional seconds to wait after start, default 5 |
| `ports` | Optional ports to publish, such as `["8080/tcp"]`, when the image declares none |
| `build` | Optional folder with a Dockerfile, for software without a published image. The tag is passed as the `VERSION` build argument |
| `info` | Optional detail the signature must report, such as `debugger console exposed`. Versions without it must not report it |

`factory/apps/werkzeug/` is an example of `build`: Werkzeug's development server, recorded with the debugger on and off.

Use at least two tags, so the draft can tell the version apart from the text around it.

## What the drafter looks for

In order of preference:

1. **The version in the reply**, such as `Server: nginx/1.27.3`. When the product's name appears earlier in the reply, the pattern requires it.
2. **A version table.** Some replies carry a numbered field that changes between releases without being the version, such as the source line in a PostgreSQL error (`L2145`). The drafter maps each value to the versions that produced it, and the signature reports that version or range, such as `16.10-16.15`. It needs identifying strings (below), and the more releases recorded, the narrower the ranges.
3. **The product alone**, from a shared start that names the product, or from identifying strings: text in every recorded version's reply and in no other image's recordings, such as `postmaster.c` and `ProcessStartupPacket`. Strings without digits are preferred, since they change least between versions.

Identifying strings are only as unique as the recordings they were checked against, so they get more trustworthy as more images are recorded.

## When no draft comes out

The drafter only handles the cases above. For anything else, write the draft by hand in `factory/drafts/IMAGE.matches`, using the same format, then run `verify`. AI assistance is fine here. `verify` is the gate either way.

```
Signatures TCP RedisInfo
match redis m|^\$.*?redis_version:(\d+(?:\.\d+)*)\r\n|s p/Redis/ v/$1/
```

`Signatures PROTOCOL PROBE` adds the matches below it to a probe from `signatures/tokmap.probes`. A signature only sees replies to its own probe.

A product that says nothing about itself in plain replies may still name itself in the certificate it generates on first start. Traefik's is `TRAEFIK DEFAULT CERT`, and Elasticsearch's is issued by `Elasticsearch security auto-configuration HTTP CA`. A signature on the `TlsClientHello` probe can read that. The generic `TLS` match is a soft match, so such a signature wins over it.

## Look-alikes

Signatures are tried in file order, and the first match wins. Some products copy another's reply: Valkey, Garnet and Dragonfly all send Redis's `redis_version` line. So `accept` places each new block ahead of the first accepted block that would otherwise name its recordings, and `verify` tests each signature at that same position. Redis's signature then sees only what the look-alikes' signatures did not claim.

## Rules

- Signatures come only from our own recordings. Do not copy or consult other scanners' signature databases.
- New probes go in `gen_probes.py`, written from the protocol's public specification and named beside the probe. Run `python factory/gen_probes.py` to regenerate `signatures/tokmap.probes`.
- The port ranking in `signatures/tcp-ports.txt`, used by `--top-ports`, `-F` and the default scan, comes from `python factory/gen_ports.py`. It reads public Docker Hub and IANA metadata only.

## Safety

Images run with their default settings, which often means no password. The factory publishes their ports on 127.0.0.1 only, and removes each container after recording. Images from outside the official library are untrusted code; run those on a disposable machine.

## Data

`factory/evidence/` and `factory/drafts/` are not committed. Each evidence folder holds `recordings.jsonl` (one reply per line, as hex) and `meta.json` (image, tag, digest, version, ports, capture time). Accepted signatures in `signatures/verified.matches` list the image digests they were tested on.
