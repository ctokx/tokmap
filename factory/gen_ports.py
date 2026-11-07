"""Writes signatures/tcp-ports.txt: tokmap's own ranking of TCP ports, most likely open first,
used by --top-ports and -F. Run from the repository root; it reads public metadata only.

1. CORE: classic network services, in tokmap's own order.
2. Ports declared (EXPOSE) by the most-pulled Docker Hub images that declare at most 20,
   ranked by how many of those images declare them, then by their total pulls.
3. IANA's registered TCP service ports, in numeric order, until there are 1000.

Usage: python factory/gen_ports.py [images per Docker Hub badge, default 500]"""
import csv, io, json, re, sys, time, urllib.error, urllib.request
from collections import defaultdict
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "signatures" / "tcp-ports.txt"
WANT = 1000
MAX_DECLARED = 20
CORE = [80, 443, 22, 21, 23, 25, 53, 3389, 445, 139, 135, 110, 143, 993, 995, 587, 465, 8080, 8443,
        3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211, 5900, 389, 636, 88, 111, 2049, 873, 161,
        5060, 5061, 1723, 3128, 1080, 8000, 8008, 8888, 9000, 9090, 9100, 631, 515, 548, 554, 1883,
        8883, 5672, 9092, 2181, 2375, 2376, 6443, 10250, 5985, 5986, 179, 500, 1194, 51820, 5353]
BADGES = ["official", "verified_publisher", "open_source"]
IANA = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"


def get_json(url):
    for attempt in range(6):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tokmap-ports"}), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(60)
                continue
            return None
        except Exception:
            time.sleep(5 * (attempt + 1))
    return None


def declared_ports(repo):
    """TCP ports declared by the newest tag of a Docker Hub repository."""
    tags = get_json(f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=1&ordering=last_updated") or {}
    results = tags.get("results") or []
    if not results:
        return set()
    layers = get_json(f"https://hub.docker.com/v2/repositories/{repo}/tags/{results[0]['name']}/images") or []
    real = next((i for i in layers if i.get("architecture") == "amd64"), layers[0] if layers else {})
    instructions = " ".join(l.get("instruction") or "" for l in real.get("layers", []))
    return {int(p) for p in re.findall(r"\b(\d{1,5})/tcp\b", instructions) if 0 < int(p) < 65536}


def pull_count(text):
    """Docker Hub's rounded counts, such as "1B+", "500M+" or "10K+", as a number."""
    m = re.fullmatch(r"([\d.]+)([KMB]?)\+?", str(text or "0"))
    return int(float(m.group(1)) * {"": 1, "K": 1e3, "M": 1e6, "B": 1e9}[m.group(2)]) if m else 0


def docker_ranking(per_badge):
    images, pulls = defaultdict(int), defaultdict(int)
    seen = set()
    for badge in BADGES:
        for start in range(0, per_badge, 100):
            page = get_json(f"https://hub.docker.com/api/search/v4?badges={badge}&type=image&size=100"
                            f"&from={start}&sort=pull_count&order=desc") or {}
            for result in page.get("results", []):
                repo = result["id"]
                if repo in seen:
                    continue
                seen.add(repo)
                declared = declared_ports(repo)
                if len(declared) > MAX_DECLARED:
                    continue  # a range of passive or relay ports says little about any one port
                for port in declared:
                    images[port] += 1
                    pulls[port] += pull_count(result.get("pull_count"))
            print(f"  {badge}: {min(start + 100, per_badge)} images read, {len(images)} ports so far", flush=True)
    return sorted(images, key=lambda p: (-images[p], -pulls[p], p)), len(seen)


def iana_ports():
    with urllib.request.urlopen(urllib.request.Request(IANA, headers={"User-Agent": "tokmap-ports"}), timeout=60) as r:
        rows = csv.DictReader(io.StringIO(r.read().decode("utf8", "replace")))
        ports = set()
        for row in rows:
            number = row.get("Port Number", "")
            if row.get("Transport Protocol") == "tcp" and row.get("Service Name") and number.isdigit():
                ports.add(int(number))
    return sorted(ports)


def merge(*rankings, want=WANT):
    out, seen = [], set()
    for ranking in rankings:
        for port in ranking:
            if port not in seen and len(out) < want:
                seen.add(port)
                out.append(port)
    return out


def main():
    per_badge = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    docker, read = docker_ranking(per_badge)
    ports = merge(CORE, docker, iana_ports())
    header = (f"# tokmap TCP port ranking, most likely open first. Written by factory/gen_ports.py on "
              f"{time.strftime('%Y-%m-%d')}:\n# {len(CORE)} classic services, then ports declared by "
              f"{read} most-pulled Docker Hub images, then IANA-registered ports.\n")
    OUT.write_text(header + "".join(f"{p}\n" for p in ports), encoding="utf8", newline="\n")
    print(f"wrote {len(ports)} ports to {OUT}")


if __name__ == "__main__":
    main()
