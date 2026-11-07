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

Use at least two tags, so the draft can tell the version apart from the text around it.

## When no draft comes out

The drafter only handles clear cases: a version visible in the reply, or a reply that names the product. For anything else, write the draft by hand in `factory/drafts/IMAGE.matches`, using the same format, then run `verify`. AI assistance is fine here. `verify` is the gate either way.

```
Signatures TCP RedisInfo
match redis m|^\$.*?redis_version:(\d+(?:\.\d+)*)\r\n|s p/Redis/ v/$1/
```

`Signatures PROTOCOL PROBE` adds the matches below it to a probe from `signatures/tokmap.probes`. A signature only sees replies to its own probe.

## Rules

- Signatures come only from our own recordings. Do not copy or consult other scanners' signature databases.
- New probes go in `gen_probes.py`, written from the protocol's public specification and named beside the probe. Run `python factory/gen_probes.py` to regenerate `signatures/tokmap.probes`.

## Safety

Images run with their default settings, which often means no password. The factory publishes their ports on 127.0.0.1 only, and removes each container after recording. Images from outside the official library are untrusted code; run those on a disposable machine.

## Data

`factory/evidence/` and `factory/drafts/` are not committed. Each evidence folder holds `recordings.jsonl` (one reply per line, as hex) and `meta.json` (image, tag, digest, version, ports, capture time). Accepted signatures in `signatures/verified.matches` list the image digests they were tested on.
