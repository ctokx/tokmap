"""Signature factory: run real software, record its replies, draft signatures, prove them.

Run from the repository root after `cargo build --release`:

  python factory/factory.py capture   start each image tag in Docker and record every probe's reply
  python factory/factory.py draft     write candidate signatures from the recordings
  python factory/factory.py verify    check drafts against all recordings
  python factory/factory.py accept    add verified drafts to signatures/verified.matches
  python factory/factory.py score     how often tokmap names the right product and version

Every command takes --only IMAGE[,IMAGE] to limit it to some images.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FACTORY = ROOT / "factory"
EVIDENCE = FACTORY / "evidence"
DRAFTS = FACTORY / "drafts"
PROBES = ROOT / "signatures" / "tokmap.probes"
VERIFIED = ROOT / "signatures" / "verified.matches"
EXE = ".exe" if os.name == "nt" else ""
TOKMAP = ROOT / "target" / "release" / f"tokmap{EXE}"
REPLAY = ROOT / "target" / "release" / f"tokmap-replay{EXE}"

MAX_START = 24
MAX_BEFORE = 32
MIN_BEFORE = 3
MAX_AFTER = 8
MIN_LITERAL = 6
MIN_PRODUCT_START = 8
CAPTURE_TRIES = 6
CAPTURE_RETRY_SECONDS = 5
REPLAY_BATCH = 200
LITERAL_SAFE = b" _-:/=,;@<>!'\"%&#~"
REGEX_SYNTAX = b".^$*+?()[]{}\\"
MAX_SIGNATURES = 3
DEFAULT_RARITY = 5


# ---------- drafting: pure functions, tested in test_factory.py

def common_prefix(items):
    if not items:
        return b""
    shortest = min(items, key=len)
    for i, byte in enumerate(shortest):
        if any(item[i] != byte for item in items):
            return shortest[:i]
    return shortest


def common_suffix(items):
    return common_prefix([item[::-1] for item in items])[::-1]


def escape(data: bytes) -> str:
    """Regex-safe text for bytes. The pattern delimiter and unreadable bytes become \\xHH."""
    out = []
    for b in data:
        char = bytes([b])
        if (chr(b).isalnum() and b < 0x80) or char in LITERAL_SAFE:
            out.append(chr(b))
        elif char in REGEX_SYNTAX:
            out.append("\\" + chr(b))
        elif char == b"\r":
            out.append("\\r")
        elif char == b"\n":
            out.append("\\n")
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def version_of(entry, tag):
    """The version a tag stands for: from the image list, else the tag without a leading v."""
    return entry.get("versions", {}).get(tag, re.sub(r"^v(?=\d)", "", tag))


def version_class(versions):
    if all(re.fullmatch(r"\d+(\.\d+)*", v) for v in versions):
        return r"\d+(?:\.\d+)*"
    return r"[\w.+~-]+"


def field(tag, value):
    delimiter = next(d for d in "/|%" if d not in value)
    return f"{tag}{delimiter}{value}{delimiter}"


def escape_any_number(data: bytes) -> str:
    """Like escape, but every number matches any number: lengths and counters change."""
    return r"\d+".join(escape(part) for part in re.split(rb"\d+", data))


def mentions(data: bytes, names) -> bool:
    return any(name.lower().encode() in data.lower() for name in names if name)


def name_before(prefixes, before_len, names):
    """(bytes naming the product as the first reply writes them, earliest offset among replies),
    found before the version context in every reply, or (b"", 0)."""
    regions = [p[:len(p) - before_len].lower() for p in prefixes]
    for name in (n.lower().encode() for n in names if n):
        if all(name in region for region in regions):
            at = regions[0].rfind(name)
            return prefixes[0][at:at + len(name)], min(region.rfind(name) for region in regions)
    return b"", 0


def versioned_pattern(samples, names=(), required=()):
    """A regex capturing the version, from (version, reply) pairs, or None if too weak.

    When the product's name appears earlier in every reply, the pattern requires it, so a
    reply shaped the same way by another product is not mistaken for this one."""
    if not samples or any(v.encode() not in data for v, data in samples):
        return None
    prefixes, suffixes = [], []
    for version, data in samples:
        at = data.find(version.encode())
        prefixes.append(data[:at])
        suffixes.append(data[at + len(version):])

    start = common_prefix(prefixes)[:MAX_START]
    rests = [p[len(start):] for p in prefixes]
    if any(r != rests[0] for r in rests):
        # A shared start that ends mid-line is often chance, like the first digit of a length.
        start = start[:start.rfind(b"\n") + 1]
        rests = [p[len(start):] for p in prefixes]
    before = common_suffix(rests)[-MAX_BEFORE:]
    # Context from the version's own line is stabler than earlier lines, which hold dates and ids.
    line_break = max(before.rfind(b"\n"), before.rfind(b"\r"))
    if line_break >= 0 and len(before) - line_break - 1 >= MIN_BEFORE:
        before = before[line_break + 1:]
    # Within a line of JSON or a list, the field name after the last separator is what stays.
    separator = max(before.rfind(b","), before.rfind(b"{"))
    if separator >= 0 and len(before) - separator - 1 >= MIN_BEFORE:
        before = before[separator + 1:]
    # In binary replies, start at the field's name: bytes before it, such as the tail of a
    # timestamp in the previous field, can match by chance.
    if b"\x00" in before:
        fields = list(re.finditer(rb"[\x20-\x7e]{4,}", before))
        if fields:
            before = before[fields[-1].start():]
    after = common_prefix(suffixes)[:MAX_AFTER]
    # The next line or field may change between releases, so stop at the end of this one.
    end = re.search(rb"\r?\n|,|\x00", after)
    if end:
        after = after[:end.end()]

    # Short binary greetings leave little fixed text around the version. Identifying strings
    # from the same reply can make up for it.
    short = len(start) + len(before) + len(after) < MIN_LITERAL
    if short and not required:
        return None
    gap = "" if all(r == rests[0] for r in rests) and rests[0] == before else ".*?"
    if not mentions(start + before + after, names):
        name, earliest = name_before(prefixes, len(before), names)
        if name:
            start = start[:earliest]  # the name may begin inside the shared start
            gap = f".*?{escape(name)}.*?"
    capture = f"({version_class([v for v, _ in samples])})"
    also = "".join(f"(?=.*?{escape(m)})" for m in required) if short else ""
    return f"^{also}{escape_any_number(start)}{gap}{escape(before)}{capture}{escape(after)}"


def product_pattern(samples, names):
    """A regex for the product alone, only when the shared start names it."""
    if len(samples) < 2:
        return None
    start = common_prefix([data for _, data in samples])[:MAX_START + MAX_BEFORE]
    if len(start) < MIN_PRODUCT_START:
        return None
    found = [start.lower().find(n.lower().encode()) for n in names if n and n.lower().encode() in start.lower()]
    if not found:
        return None
    # Only the line that names the product: earlier lines may carry a date or a counter.
    at = min(found)
    line_start = max(start.rfind(b"\n", 0, at), start.rfind(b"\x00", 0, at)) + 1
    ends = [i for i in (start.find(b"\r", at), start.find(b"\n", at), start.find(b"\x00", at)) if i >= 0]
    line = escape_any_number(start[line_start:min(ends, default=len(start))])
    return f"^{line}" if line_start == 0 else f"^{escape(start[:1])}.*?{line}"


def probe_rarities(text):
    """{probe name: rarity} from a probes file. Lower means sent more often."""
    rarities, current = {}, None
    for line in text.splitlines():
        if line.startswith("Probe "):
            current = line.split()[2]
            rarities[current] = 0 if line.rstrip().endswith("q||") else DEFAULT_RARITY
        elif line.startswith("rarity ") and current:
            rarities[current] = int(line.split()[1])
    return rarities


TOKEN_SPLIT = re.compile(rb"[\x00\r\n]+")
MIN_MARKER = 6
MAX_MARKERS = 2


def tokens(data: bytes):
    """Printable runs between NULs and line breaks: the fields of most replies."""
    return [t for t in TOKEN_SPLIT.split(data) if t and all(32 <= b < 127 for b in t)]


def markers(samples, others):
    """Up to two strings in every reply of this product and in no other product's replies,
    in the order they appear, such as source file and function names in an error."""
    shared = set(tokens(samples[0][1]))
    for _, data in samples[1:]:
        shared &= set(tokens(data))
    unique = [t for t in shared if len(t) >= MIN_MARKER and not any(t in other for other in others)]
    # Strings without digits change least between versions.
    chosen = sorted(unique, key=lambda t: (any(48 <= b <= 57 for b in t), -len(t)))[:MAX_MARKERS]
    chosen.sort(key=lambda t: samples[0][1].find(t))
    for _, data in samples:
        at = [data.find(t) for t in chosen]
        if at != sorted(at):
            return []
    return chosen


def numbered_fields(data: bytes):
    """{prefix: number} for fields made of a short label and a number, such as L2145."""
    found = {}
    for token in tokens(data):
        m = re.fullmatch(rb"([A-Za-z_]{1,12}[:=]?)(\d{2,})", token)
        if m:
            found.setdefault(m.group(1), set()).add(m.group(2))
    return {prefix: values.pop() for prefix, values in found.items() if len(values) == 1}


def version_key(version):
    return tuple(int(x) for x in re.findall(r"\d+", version))


def version_text(versions, all_versions):
    """The versions sharing one field value, as text.

    Unrecorded releases may share the value too. Between recorded neighbours that is bounded:
    `16.11-16.13`. At the edge of what was recorded for a major version it is not, so the
    open side says so: `17.9 or earlier`, `18.6 or later`, or `17.x` when both sides are open.
    Values shared across major versions are listed: `16.4, 17.0`."""
    ordered = sorted(versions, key=version_key)
    majors = {version_key(v)[:1] for v in ordered}
    if len(majors) > 1:
        return ", ".join(ordered)
    major = majors.pop()
    same_major = [version_key(v) for v in all_versions if version_key(v)[:1] == major]
    low, high = version_key(ordered[0]), version_key(ordered[-1])
    if sorted(k for k in same_major if low <= k <= high) != sorted(version_key(v) for v in ordered):
        return ", ".join(ordered)
    open_low, open_high = low == min(same_major), high == max(same_major)
    if open_low and open_high:
        return f"{major[0]}.x"
    if open_low:
        return f"{ordered[-1]} or earlier"
    if open_high:
        return f"{ordered[0]} or later"
    return ordered[0] if len(ordered) == 1 else f"{ordered[0]}-{ordered[-1]}"


def version_table(samples):
    """{field value: versions} for a numbered field that differs between versions, or {}.
    Source line numbers in error replies change when the file changes between releases."""
    fields = [numbered_fields(data) for _, data in samples]
    prefixes = set(fields[0])
    for f in fields[1:]:
        prefixes &= set(f)
    best = {}
    for prefix in prefixes:
        table = {}
        for (version, _), f in zip(samples, fields):
            table.setdefault(prefix + f[prefix], set()).add(version)
        if 1 < len(table) and len(table) > len(best):
            best = table
    return best


def table_lines(samples, others, start_byte):
    """(pattern, version text) pairs for a version table, then the product-only pattern."""
    found = markers(samples, others)
    if not found:
        return []
    head = f"^{escape(start_byte)}"
    rest = "".join(f".*?{escape(m)}" for m in found)
    edge = r"[\x00\r\n]"
    table = version_table(samples)
    all_versions = [v for v, _ in samples]
    lines = [(f"{head}(?=.*?{edge}{escape(value)}{edge}){rest}", version_text(versions, all_versions))
             for value, versions in sorted(table.items())]
    return lines + [(f"{head}{rest}", None)]


def draft_signature(entry, evidence, rarities=None, others=()):
    """Signatures for one image, from {tag: [recordings]}, as file text, or None.

    In order of preference: a pattern that reads the version from the reply, a table that
    maps a numbered field to versions, then the product alone. Prefers probes sent most
    often, and keeps a few versioned patterns, so the product is still named when one reply
    differs in a real deployment. `others` holds other products' replies, so identifying
    strings can be checked to be unique."""
    rarities = rarities or {}
    groups = {}
    for tag, recordings in evidence.items():
        version = version_of(entry, tag)
        for r in recordings:
            key = (r["protocol"].upper(), r["probe"])
            reply = bytes.fromhex(r["response_hex"])
            by_tag = groups.setdefault(key, {})
            # A probe may be answered on several ports: keep the reply that shows the version.
            if tag not in by_tag or (version.encode() in reply and version.encode() not in by_tag[tag][1]):
                by_tag[tag] = (version, reply)

    candidates = []
    product_names = [entry["product"], entry["image"].split("/")[-1]]
    for (protocol, probe), by_tag in groups.items():
        if len(by_tag) < len(evidence):
            continue  # every recorded tag must have answered this probe
        samples = list(by_tag.values())
        rarity = rarities.get(probe, DEFAULT_RARITY)
        found = markers(samples, others) if others else []
        pattern = versioned_pattern(samples, product_names, found)
        if pattern:
            # Patterns that name the product rank first: they are least likely to match others.
            nameless = not any(n.lower() in pattern.lower() for n in product_names)
            candidates.append((0, nameless, rarity, -len(pattern), protocol, probe, [(pattern, "$1")]))
            continue
        start = common_prefix([data for _, data in samples])[:1]
        lines = table_lines(samples, others, start) if start else []
        if len(lines) > 1:
            candidates.append((1, False, rarity, -len(lines), protocol, probe, lines))
            continue
        pattern = product_pattern(samples, product_names)  # not the service: "http" starts every HTTP reply
        if pattern or lines:
            chosen = [(pattern, None)] if pattern else lines
            candidates.append((2, False, rarity, -len(chosen[0][0]), protocol, probe, chosen))
    if not candidates:
        return None

    candidates.sort()
    kind = candidates[0][0]
    keep = MAX_SIGNATURES if kind == 0 else 1
    text = f"# Draft for {entry['image']} from tags {', '.join(sorted(evidence))}. Not verified.\n"
    for *_, protocol, probe, lines in [c for c in candidates if c[0] == kind][:keep]:
        text += f"Signatures {protocol} {probe}\n"
        for pattern, version in lines:
            info = f" {field('p', entry['product'])}" + (f" {field('v', version)}" if version else "")
            text += f"match {entry['service']} m|{pattern}|s{info}\n"
    return text


# ---------- evidence

def load_images(path, only):
    images = json.loads(Path(path).read_text(encoding="utf8"))
    if only:
        wanted = set(only.split(","))
        images = [i for i in images if i["image"] in wanted]
    return images


def slug(image):
    return image.replace("/", "_")


def load_evidence(image):
    """{tag: [recordings]} for one image."""
    found = {}
    for meta in sorted((EVIDENCE / slug(image)).glob("*/meta.json")):
        lines = (meta.parent / "recordings.jsonl").read_text(encoding="utf8").splitlines()
        found[meta.parent.name] = [json.loads(line) for line in lines if line.strip()]
    return found


def image_ref(entry, tag):
    """The image to run: a published one, or one built from a Dockerfile in factory/apps/."""
    if entry.get("build"):
        return f"tokmap-factory/{Path(entry['build']).name}:{tag}"
    return f"{entry['image']}:{tag}"


def listed_evidence(entry):
    """Evidence for the tags the image list names only, so other recorded tags can be held out."""
    return {tag: recs for tag, recs in load_evidence(entry["image"]).items() if tag in entry["tags"]}


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def exposed_ports(entry, ref):
    """Ports to publish: the image list's own, else the image's EXPOSE lines."""
    if entry.get("ports"):
        return entry["ports"]
    exposed = json.loads(docker("image", "inspect", "--format", "{{json .Config.ExposedPorts}}", ref) or "null")
    return sorted(exposed or {})


def mapped_ports(container):
    """{host port: (container port, protocol)} for every published IPv4 port."""
    ports = {}
    for line in docker("port", container).splitlines():
        m = re.match(r"(\d+)/(tcp|udp) -> 127\.0\.0\.1:(\d+)", line)
        if m:
            ports[int(m.group(3))] = (int(m.group(1)), m.group(2))
    return ports


def record_once(ports, out_dir):
    tcp = [str(h) for h, (_, proto) in ports.items() if proto == "tcp"]
    udp = [str(h) for h, (_, proto) in ports.items() if proto == "udp"]
    spec = ",".join(([f"T:{','.join(tcp)}"] if tcp else []) + ([f"U:{','.join(udp)}"] if udp else []))
    command = [str(TOKMAP), "-t", "127.0.0.1", "-p", spec, "--connect", "-P", "-n",
               "--record", out_dir, "--json-only"] + (["--udp"] if udp else [])
    subprocess.run(command, capture_output=True, timeout=600)
    path = Path(out_dir) / "127.0.0.1.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf8").splitlines() if l.strip()] if path.exists() else []


def capture(entry, tag, force, prune):
    ref = image_ref(entry, tag)
    out = EVIDENCE / slug(entry["image"]) / tag
    if (out / "meta.json").exists() and not force:
        print(f"  {ref}: already captured")
        return
    if entry.get("build"):
        docker("build", "-q", "-t", ref, "--build-arg", f"VERSION={tag}", str(ROOT / entry["build"]))
    else:
        docker("pull", ref)
    digests = json.loads(docker("image", "inspect", "--format", "{{json .RepoDigests}}", ref) or "[]")
    digests = digests or [docker("image", "inspect", "--format", "{{.Id}}", ref)]
    env = [arg for key, value in entry.get("env", {}).items() for arg in ("-e", f"{key}={value}")]
    # Loopback only: these images run with default settings, often without a password.
    publish = [arg for port in exposed_ports(entry, ref) for arg in ("-p", f"127.0.0.1::{port}")]
    container = docker("run", "-d", *publish, *env, ref, *entry.get("args", []))
    try:
        ports = mapped_ports(container)
        if not ports:
            raise RuntimeError("image publishes no ports")
        time.sleep(entry.get("settle", 5))
        with tempfile.TemporaryDirectory() as scratch:
            recordings = []
            for _ in range(CAPTURE_TRIES):
                recordings = record_once(ports, scratch)
                if recordings:
                    break
                time.sleep(CAPTURE_RETRY_SECONDS)
        if not recordings:
            raise RuntimeError("no probe got a reply")
        for r in recordings:
            r["port"] = ports.get(r["port"], (r["port"],))[0]  # host port back to container port
        out.mkdir(parents=True, exist_ok=True)
        (out / "recordings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recordings), encoding="utf8")
        meta = {
            "image": entry["image"], "tag": tag, "digest": digests[0] if digests else None,
            "product": entry["product"], "version": version_of(entry, tag),
            "service": entry["service"], "info": entry.get("info"),
            "ports": sorted({f"{p}/{proto}" for p, proto in ports.values()}),
            "captured": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf8")
        print(f"  {ref}: {len(recordings)} replies recorded")
    finally:
        docker("rm", "-f", container, check=False)
        if prune:
            docker("rmi", ref, check=False)


# ---------- replay and checking

def replay(signature_files, recording_files):
    results = []
    files = [str(f) for f in recording_files]
    for i in range(0, len(files), REPLAY_BATCH):
        command = [str(REPLAY)]
        for f in signature_files:
            command += ["--signatures", str(f)]
        result = subprocess.run(command + files[i:i + REPLAY_BATCH], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"tokmap-replay failed: {result.stderr.strip()}")
        results += [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return results


def all_recording_files():
    # A capture still in progress has replies but no meta.json yet.
    return sorted(p for p in EVIDENCE.glob("*/*/recordings.jsonl") if (p.parent / "meta.json").exists())


def identify(matches):
    """The best (product, version, detail) from one tag's replay results. Hard matches beat soft
    ones, then matches with detail, then matches with a version, as in tokmap itself."""
    found = [m["match"] for m in matches if m["match"]]
    found.sort(key=lambda m: (m["confidence"] == "high", m.get("info") is not None,
                              m.get("version") is not None), reverse=True)
    if not found:
        return None, None, None
    return found[0].get("product") or found[0]["service_name"], found[0].get("version"), found[0].get("info")


def version_matches(found, truth):
    """Whether a reported version or range contains the true version: `a-b`, `a, b`,
    `a or earlier` and `a or later` within a's major version, or `17.x`."""
    if not found or not truth:
        return found == truth
    key = version_key(truth)
    if found == truth or truth in [v.strip() for v in found.split(",")]:
        return True
    if m := re.fullmatch(r"(\d+)\.x", found):
        return key[:1] == (int(m.group(1)),)
    if m := re.fullmatch(r"([\d.]+) or (earlier|later)", found):
        bound = version_key(m.group(1))
        return key[:1] == bound[:1] and (key <= bound if m.group(2) == "earlier" else key >= bound)
    m = re.fullmatch(r"([\d.]+)-([\d.]+)", found)
    return bool(m) and version_key(m.group(1)) <= key <= version_key(m.group(2))


def judge(results, signature_product):
    """Per tag: whether the product and version came out right, plus false positives elsewhere."""
    by_file = {}
    for r in results:
        by_file.setdefault(r["file"], []).append(r)
    report, false_positives = [], []
    for path, matches in sorted(by_file.items()):
        meta = json.loads((Path(path).parent / "meta.json").read_text(encoding="utf8"))
        product, version, info = identify(matches)
        if signature_product and meta["product"] != signature_product:
            if any(m["match"] and m["match"].get("product") == signature_product for m in matches):
                false_positives.append(f"{meta['image']}:{meta['tag']}")
            continue
        expected_info = meta.get("info")
        report.append({"image": meta["image"], "tag": meta["tag"],
                       "expected": [meta["product"], meta["version"], expected_info],
                       "found": [product, version, info], "product_ok": product == meta["product"],
                       "version_ok": version_matches(version, meta["version"]),
                       "version_exact": version == meta["version"], "info_ok": info == expected_info})
    return report, false_positives


def split_blocks(text):
    """A draft's signatures, one `Signatures` line with its match lines per block."""
    blocks = []
    for line in text.splitlines():
        if line.startswith("Signatures "):
            blocks.append([line])
        elif blocks and line.startswith(("match ", "softmatch ")):
            blocks[-1].append(line)
    return ["\n".join(block) + "\n" for block in blocks]


def check_block(entry, block, recordings):
    """(tags this signature names correctly, problems). Any problem rejects the signature."""
    with tempfile.NamedTemporaryFile("w", suffix=".matches", delete=False, encoding="utf8") as f:
        f.write(block)
    try:
        report, false_positives = judge(replay([PROBES, VERIFIED, f.name], recordings), entry["product"])
    finally:
        os.unlink(f.name)
    # Recorded tags the entry does not list are held out for testing, so they must not
    # decide which signatures are kept.
    report = [r for r in report if r["image"] != entry["image"] or r["tag"] in entry["tags"]]
    has_version = re.search(r"\sv[/|%]", block) is not None
    mine = [r for r in report if r["image"] == entry["image"] and r["product_ok"]]
    problems = [f"{r['tag']}: expected {r['expected']}, found {r['found']}"
                for r in mine if (has_version and not r["version_ok"]) or not r["info_ok"]]
    problems += [f"also matched {fp}" for fp in false_positives]
    # Another image of the same product: claiming the wrong detail or version there is wrong,
    # while reporting less, such as no detail, is not.
    problems += [f"wrong for {r['image']}:{r['tag']}: expected {r['expected']}, found {r['found']}"
                 for r in report if r["image"] != entry["image"] and r["product_ok"]
                 and (r["found"][2] not in (None, r["expected"][2]) or (r["found"][1] and not r["version_ok"]))]
    return {r["tag"] for r in mine}, problems


def verify(entry):
    """Keeps each signature that is right wherever it matches and matches no other image.
    Passes when the kept signatures name every recorded tag."""
    draft = DRAFTS / f"{slug(entry['image'])}.matches"
    if not draft.exists():
        print(f"  {entry['image']}: no draft")
        return False
    recordings = all_recording_files()
    tags = set(listed_evidence(entry))
    kept, covered = [], set()
    for block in split_blocks(draft.read_text(encoding="utf8")):
        named, problems = check_block(entry, block, recordings)
        if problems or not named:
            print(f"    dropped {block.splitlines()[0]}: {'; '.join(problems) or 'names no tag'}")
            continue
        kept.append(block)
        covered |= named
    ok = bool(kept) and tags <= covered
    print(f"  {entry['image']}: {'PASS' if ok else 'FAIL'} ({len(covered)} of {len(tags)} tags, "
          f"{len(kept)} signatures kept)")
    if kept:
        header = draft.read_text(encoding="utf8").splitlines()[0]
        draft.write_text(header + "\n" + "".join(kept), encoding="utf8", newline="\n")
    return ok


def names_product(block, entry):
    """Whether a signature's pattern contains the product's name. Ones that do not could match
    another product shaped the same way, which a small set of recordings may not reveal."""
    patterns = " ".join(re.findall(r"^(?:soft)?match \S+ m\|([^|]*)\|", block, re.M)).lower()
    return any(name.lower() in patterns for name in (entry["product"], entry["image"].split("/")[-1]))


def accept(entry, reviewed):
    if not verify(entry):
        return
    draft = (DRAFTS / f"{slug(entry['image'])}.matches").read_text(encoding="utf8")
    if not reviewed and not all(names_product(b, entry) for b in split_blocks(draft)):
        print(f"  {entry['image']}: not accepted, a signature does not contain the product name. "
              "Check it by hand, then accept with --reviewed.")
        return
    evidence = sorted(EVIDENCE.glob(f"{slug(entry['image'])}/*/meta.json"))
    proven = [json.loads(m.read_text(encoding="utf8")) for m in evidence]
    body = "\n".join(line for line in draft.splitlines() if not line.startswith("#"))
    tested = "\n".join(f"# tested: {m['image']}:{m['tag']} {m['digest']}" for m in proven)
    block = f"# BEGIN {entry['image']}\n{tested}\n{body}\n# END {entry['image']}\n"

    text = VERIFIED.read_text(encoding="utf8")
    text = re.sub(rf"# BEGIN {re.escape(entry['image'])}\n.*?# END {re.escape(entry['image'])}\n", "", text, flags=re.S)
    VERIFIED.write_text(text.rstrip("\n") + "\n\n" + block, encoding="utf8", newline="\n")
    print(f"  {entry['image']}: accepted")


def score(images):
    results = replay([PROBES, VERIFIED], all_recording_files())
    report, _ = judge(results, None)
    wanted = {i["image"] for i in images}
    report = [r for r in report if r["image"] in wanted]
    for r in report:
        mark = "ok" if r["product_ok"] and r["version_ok"] and r["info_ok"] else ("product only" if r["product_ok"] else "miss")
        print(f"  {r['image']}:{r['tag']:<12} {mark:<13} found {r['found']}")
    total = len(report) or 1
    print(f"\n  tags: {len(report)}  product right: {sum(r['product_ok'] for r in report) * 100 // total}%"
          f"  version right: {sum(r['product_ok'] and r['version_ok'] for r in report) * 100 // total}%")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["capture", "draft", "verify", "accept", "score"])
    parser.add_argument("--images", default=str(FACTORY / "images.json"))
    parser.add_argument("--only", help="comma-separated image names")
    parser.add_argument("--force", action="store_true", help="capture again even if evidence exists")
    parser.add_argument("--prune", action="store_true", help="delete each image after capturing it")
    parser.add_argument("--reviewed", action="store_true",
                        help="accept signatures that do not contain the product name, after checking them")
    args = parser.parse_args()
    images = load_images(args.images, args.only)

    if args.command == "capture":
        for entry in images:
            for tag in entry["tags"]:
                try:
                    capture(entry, tag, args.force, args.prune)
                except Exception as error:
                    print(f"  {entry['image']}:{tag}: FAILED, {error}")
    elif args.command == "draft":
        DRAFTS.mkdir(exist_ok=True)
        rarities = probe_rarities(PROBES.read_text(encoding="utf8"))
        replies = {path.parent.parent.name: [] for path in all_recording_files()}
        for path in all_recording_files():
            for line in path.read_text(encoding="utf8").splitlines():
                if line.strip():
                    replies[path.parent.parent.name].append(bytes.fromhex(json.loads(line)["response_hex"]))
        for entry in images:
            others = [reply for image, found in replies.items() if image != slug(entry["image"]) for reply in found]
            text = draft_signature(entry, listed_evidence(entry), rarities, others)
            draft = DRAFTS / f"{slug(entry['image'])}.matches"
            if text:
                draft.write_text(text, encoding="utf8", newline="\n")
            elif draft.exists():
                draft.unlink()  # an old draft must not be verified as if it were new
            print(f"  {entry['image']}: {'drafted' if text else 'no clear signature, needs a hand-written draft'}")
    elif args.command == "verify":
        failed = [e["image"] for e in images if not verify(e)]
        sys.exit(1 if failed else 0)
    elif args.command == "accept":
        for entry in images:
            accept(entry, args.reviewed)
    else:
        score(images)


if __name__ == "__main__":
    main()
