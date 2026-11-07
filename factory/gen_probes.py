"""Writes signatures/tokmap.probes. Payloads are computed here so binary lengths are always right.

Each probe follows a public protocol specification, named in the comment beside it.
Run from the repository root: python factory/gen_probes.py
"""
import os
import struct


def escape(data: bytes) -> str:
    out = []
    for b in data:
        c = chr(b)
        if c == "\r":
            out.append("\\r")
        elif c == "\n":
            out.append("\\n")
        elif c in "\\|" or b < 0x20 or b > 0x7E:
            out.append(f"\\x{b:02x}")
        else:
            out.append(c)
    return "".join(out)


def ber(tag, content):
    assert len(content) < 128, "short-form BER length only"
    return bytes([tag, len(content)]) + content


def http(path, method="GET"):
    return (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: tokmap\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n").encode()


def mongo_build_info():
    doc = (b"\x10buildInfo\x00" + struct.pack("<i", 1)
           + b"\x02$db\x00" + struct.pack("<i", 6) + b"admin\x00" + b"\x00")
    doc = struct.pack("<i", len(doc) + 4) + doc
    body = struct.pack("<I", 0) + b"\x00" + doc
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2013) + body


def ldap_root_dse():
    attributes = ber(0x30, ber(0x04, b"vendorName") + ber(0x04, b"vendorVersion"))
    search = (ber(0x04, b"") + ber(0x0A, b"\x00") + ber(0x0A, b"\x00") + ber(0x02, b"\x00")
              + ber(0x02, b"\x00") + ber(0x01, b"\x00") + ber(0x87, b"objectClass") + attributes)
    return ber(0x30, ber(0x02, b"\x01") + ber(0x63, search))


def tls_client_hello():
    extensions = (struct.pack(">HHHH", 0x000A, 4, 2, 0x001D)
                  + struct.pack(">HHHHHH", 0x000D, 8, 6, 0x0403, 0x0804, 0x0401))
    random_bytes = b"tokmap-client-hello-random-bytes"
    assert len(random_bytes) == 32
    hello = (b"\x03\x03" + random_bytes + b"\x00"
             + struct.pack(">H", 8) + bytes.fromhex("c02fc030009c1301") + b"\x01\x00"
             + struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def postgres_startup(version):
    params = b"user\x00tokmap\x00database\x00tokmap\x00\x00"
    return struct.pack(">II", 8 + len(params), version) + params


def dns_query(labels, qtype):
    query = b"tk\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in labels:
        query += bytes([len(label)]) + label
    return query + b"\x00" + struct.pack(">HH", qtype, 1)


def snmp_sysdescr():
    binding = ber(0x30, ber(0x06, bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])) + ber(0x05, b""))
    pdu = ber(0x02, b"\x54\x4b") + ber(0x02, b"\x00") + ber(0x02, b"\x00") + ber(0x30, binding)
    return ber(0x30, ber(0x02, b"\x01") + ber(0x04, b"public") + ber(0xA0, pdu))


WEB_PORTS = "80,81,591,3000,4200,5000,5173,8000,8008,8080,8081,8088,8888,9000,9090"

# name, payload, rarity, ports, TLS ports, source
TCP = [
    ("HttpRoot", http("/"), 1, WEB_PORTS, "443,8443,9443", "RFC 9110"),
    ("HttpConsole", http("/console"), 3, "", "",
     "path of the debugger console in Werkzeug, which serves Flask in development; read only"),
    ("HttpHead", http("/", "HEAD"), 2, "", "", "RFC 9110"),
    ("HttpOptions", http("/", "OPTIONS"), 3, "", "", "RFC 9110"),
    ("HttpMissing", http("/tokmap-no-such-path"), 2, "", "", "RFC 9110; error pages often name the server"),
    ("HttpVersion", http("/version"), 4, "", "", "version endpoint common to many services"),
    ("HttpApiVersion", http("/api/version"), 4, "", "", "version endpoint common to many services"),
    ("HttpApiHealth", http("/api/health"), 5, "", "", "health endpoint common to many services"),
    ("HttpHealth", http("/health"), 5, "", "", "health endpoint common to many services"),
    ("HttpStatus", http("/status"), 5, "", "", "status endpoint common to many services"),
    ("HttpMetrics", http("/metrics"), 5, "", "", "OpenMetrics exposition"),
    ("HttpActuatorInfo", http("/actuator/info"), 6, "", "", "Spring Boot actuator"),
    ("HttpVaultHealth", http("/v1/sys/health"), 6, "8200", "8200", "Vault HTTP API"),
    ("HttpRegistry", http("/v2/"), 6, "5000", "5000", "OCI distribution specification"),
    ("HttpNextcloudStatus", http("/status.php"), 6, "", "", "Nextcloud status endpoint, in its admin manual"),
    ("HttpSolrSystem", http("/solr/admin/info/system"), 6, "8983", "", "Solr system information API, in its reference guide"),
    ("HttpWordPressSetup", http("/wp-admin/setup-config.php"), 6, "", "",
     "WordPress setup page, where every page redirects until a database is configured; read only"),
    ("Lines", b"\r\n\r\n", 1, "", "", "bare line endings, which text protocols answer with an error"),
    ("TlsClientHello", tls_client_hello(), 1, "", "", "RFC 8446 and RFC 5246"),
    ("RedisPing", b"*1\r\n$4\r\nPING\r\n", 3, "6379", "", "RESP protocol"),
    ("RedisInfo", b"*1\r\n$4\r\nINFO\r\n", 3, "6379", "", "RESP protocol"),
    ("PostgresSsl", struct.pack(">II", 8, 80877103), 3, "5432", "", "PostgreSQL frontend/backend protocol"),
    ("PostgresStartup", postgres_startup(196608), 3, "5432", "", "PostgreSQL frontend/backend protocol"),
    ("PostgresBadVersion", postgres_startup(0xFFFF0000), 4, "5432", "",
     "PostgreSQL frontend/backend protocol; unknown versions are refused with the supported range"),
    ("MongoBuildInfo", mongo_build_info(), 3, "27017", "", "MongoDB wire protocol, OP_MSG"),
    ("Amqp091", b"AMQP\x00\x00\x09\x01", 3, "5672", "5671", "AMQP 0-9-1"),
    ("MqttConnect", b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06tokmap", 3, "1883", "8883", "MQTT 3.1.1"),
    ("MemcachedVersion", b"version\r\n", 3, "11211", "", "memcached text protocol"),
    ("ZookeeperSrvr", b"srvr", 4, "2181", "", "ZooKeeper four letter commands"),
    ("KafkaApiVersions", b"\x00\x00\x00\x10\x00\x12\x00\x00\x00\x00\x00\x01\x00\x06tokmap", 4, "9092", "",
     "Kafka protocol, ApiVersions v0"),
    ("CassandraOptions", b"\x04\x00\x00\x01\x05\x00\x00\x00\x00", 4, "9042", "", "CQL binary protocol v4"),
    ("LdapRootDse", ldap_root_dse(), 4, "389", "636", "RFC 4511"),
    ("SmtpEhlo", b"EHLO tokmap.invalid\r\n", 4, "25,465,587,1025,2525", "465", "RFC 5321"),
    ("RtspOptions", b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", 5, "554,8554", "", "RFC 2326"),
]

# name, payload, rarity, ports, source
UDP = [
    ("DnsRootNs", dns_query([], 2), 1, "53", "RFC 1035"),
    ("NtpClient", b"\x23" + b"\x00" * 47, 1, "123", "RFC 5905"),
    ("SnmpSysDescr", snmp_sysdescr(), 1, "161", "RFC 3416"),
    ("MemcachedUdp", b"\x74\x6b\x00\x00\x00\x01\x00\x00version\r\n", 3, "11211", "memcached UDP framing"),
]


def render():
    lines = [
        "# tokmap service probes. Generated by factory/gen_probes.py; edit that file instead.",
        "# Signatures for these probes live in verified.matches and come from factory/.",
        "",
        "# Printer ports print whatever they receive.",
        "Exclude T:9100-9107",
        "",
        "# Sends nothing, for services that speak first.",
        "Probe TCP Empty q||",
        "totalwaitms 6000",
        "",
    ]
    for name, payload, rarity, ports, tls_ports, source in TCP:
        lines += [f"# {source}", f"Probe TCP {name} q|{escape(payload)}|", f"rarity {rarity}"]
        if ports:
            lines.append(f"ports {ports}")
        if tls_ports:
            lines.append(f"sslports {tls_ports}")
        if name == "TlsClientHello":
            # A handshake record or an alert means the port speaks TLS. Soft, so a signature
            # for the product behind it, such as one reading its certificate, wins.
            lines += [r"softmatch ssl m|^\x16\x03[\x00-\x04]|s p/TLS/", r"softmatch ssl m|^\x15\x03[\x00-\x04]|s p/TLS/"]
        lines.append("")
    for name, payload, rarity, ports, source in UDP:
        lines += [f"# {source}", f"Probe UDP {name} q|{escape(payload)}|", f"rarity {rarity}", f"ports {ports}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    os.makedirs("signatures", exist_ok=True)
    with open("signatures/tokmap.probes", "w", encoding="utf8", newline="\n") as f:
        f.write(render())
    print(f"{len(TCP) + 1} TCP probes, {len(UDP)} UDP probes")
