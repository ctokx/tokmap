import re
import unittest

from factory import (draft_signature, escape, markers, names_product, probe_rarities, product_pattern, split_blocks,
                     table_lines, version_matches, version_table, version_text,
                     version_of, versioned_pattern)

REDIS = {"image": "redis", "service": "redis", "product": "Redis", "tags": []}


def info(version, uptime):
    return f"$400\r\n# Server\r\nredis_version:{version}\r\nuptime_in_seconds:{uptime}\r\n".encode()


def http(version, date):
    return f"HTTP/1.1 200 OK\r\nDate: {date}\r\nServer: nginx/{version}\r\n\r\n".encode()


def matches(pattern, data):
    return re.search(pattern.encode(), data, re.S)


class DraftTests(unittest.TestCase):
    def test_versioned_pattern_captures_every_version(self):
        samples = [("7.2.4", info("7.2.4", 5)), ("6.2.14", info("6.2.14", 917))]
        pattern = versioned_pattern(samples)
        for version, data in samples:
            self.assertEqual(matches(pattern, data).group(1).decode(), version)

    def test_context_skips_lines_that_change(self):
        samples = [("1.25.3", http("1.25.3", "Fri, 06 Nov")), ("1.24.0", http("1.24.0", "Mon, 01 Jan"))]
        pattern = versioned_pattern(samples)
        self.assertIn("Server: nginx/", pattern)
        self.assertNotIn("Nov", pattern)
        self.assertEqual(matches(pattern, http("1.27.0", "Tue, 02 Feb")).group(1), b"1.27.0")

    def test_other_products_do_not_match(self):
        pattern = versioned_pattern([("1.25.3", http("1.25.3", "a")), ("1.24.0", http("1.24.0", "b"))])
        self.assertIsNone(matches(pattern, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n\r\n"))

    def test_a_shared_digit_of_a_length_is_not_used(self):
        samples = [("8.1.0", b"$5539\r\nvalkey_version:8.1.0\r\n"), ("7.2.7", b"$5102\r\nvalkey_version:7.2.7\r\n")]
        pattern = versioned_pattern(samples)
        self.assertEqual(matches(pattern, b"$4012\r\nvalkey_version:9.0.0\r\n").group(1), b"9.0.0")

    def test_json_context_keeps_only_the_field_name(self):
        def reply(version, date):
            return f'{{"commitDate":"{date}.000000000Z","pkgVersion":"{version}"}}'.encode()
        pattern = versioned_pattern([("1.12.0", reply("1.12.0", "2024-12-23")), ("1.11.3", reply("1.11.3", "2024-11-14"))])
        self.assertNotIn("000Z", pattern)
        self.assertEqual(matches(pattern, b'{"commitDate":"2025-01-01T00:00:00Z","pkgVersion":"1.13.0"}').group(1), b"1.13.0")

    def test_numbers_in_the_shared_start_match_any_number(self):
        def reply(version):
            return f"$3590\r\n# Server\r\ngarnet_version:{version}\r\nos:Unix".encode()
        pattern = versioned_pattern([("1.0.46", reply("1.0.46")), ("1.0.44", reply("1.0.44"))])
        later = b"$3604\r\n# Server\r\ngarnet_version:1.0.50\r\nos:Unix"
        self.assertEqual(matches(pattern, later).group(1), b"1.0.50")

    def test_product_name_earlier_in_the_reply_is_required(self):
        def reply(name, version):
            return f'{{"distribution" : "{name}",\n    "number" : "{version}",\n    "build"'.encode()
        samples = [("2.18.0", reply("opensearch", "2.18.0")), ("2.17.1", reply("opensearch", "2.17.1"))]
        pattern = versioned_pattern(samples, ["OpenSearch"])
        self.assertIn("opensearch", pattern)
        self.assertTrue(matches(pattern, reply("opensearch", "2.19.0")))
        self.assertIsNone(matches(pattern, reply("elasticsearch-like", "8.15.0").replace(b"opensearch", b"other")))

    def test_signatures_that_name_the_product_rank_first(self):
        def tagged(version):
            return [{"protocol": "tcp", "probe": "Plain", "response_hex": f'HTTP/1.1 200 OK\r\n\r\n{{"version":"{version}"}}'.encode().hex()},
                    {"protocol": "tcp", "probe": "Named", "response_hex": f'HTTP/1.1 200 OK\r\n\r\n{{"title":"qdrant","version":"{version}"}}'.encode().hex()}]
        evidence = {"1.12.4": tagged("1.12.4"), "1.11.5": tagged("1.11.5")}
        text = draft_signature({"image": "qdrant/qdrant", "service": "http", "product": "Qdrant"}, evidence)
        self.assertEqual(re.findall(r"Signatures TCP (\w+)", text)[0], "Named")

    def test_drafts_split_into_one_block_per_signature(self):
        text = "# header\nSignatures TCP A\nmatch x m|a|\nSignatures TCP B\nmatch y m|b|\nsoftmatch y m|c|\n"
        self.assertEqual(split_blocks(text), ["Signatures TCP A\nmatch x m|a|\n",
                                              "Signatures TCP B\nmatch y m|b|\nsoftmatch y m|c|\n"])

    def test_signatures_without_the_product_name_are_flagged(self):
        entry = {"product": "Ollama", "image": "ollama/ollama"}
        nameless = 'Signatures TCP X\nmatch http m|"version":"(\\d+)"|s p/Ollama/ v/$1/\n'
        named = 'Signatures TCP X\nmatch http m|ollama.*?"version":"(\\d+)"|s p/Ollama/ v/$1/\n'
        self.assertFalse(names_product(nameless, entry))
        self.assertTrue(names_product(named, entry))

    def pg_error(self, line):
        body = (b"SFATAL\x00VFATAL\x00C0A000\x00Munsupported frontend protocol 65535.0\x00"
                b"Fpostmaster.c\x00L" + str(line).encode() + b"\x00RProcessStartupPacket\x00\x00")
        return b"E\x00\x00\x00" + bytes([len(body) + 4]) + body

    def test_markers_are_shared_by_every_version_and_absent_elsewhere(self):
        samples = [("16.6", self.pg_error(2145)), ("15.10", self.pg_error(2198))]
        others = [b"-ERR unknown command 'FATAL'", b"HTTP/1.1 400 Bad Request\r\n\r\nunsupported frontend protocol"]
        found = markers(samples, others)
        self.assertIn(b"RProcessStartupPacket", found)
        self.assertNotIn(b"L2145", found)

    def test_version_table_maps_a_numbered_field_to_versions(self):
        samples = [("16.4", self.pg_error(2145)), ("16.6", self.pg_error(2145)), ("15.10", self.pg_error(2198))]
        self.assertEqual(version_table(samples), {b"L2145": {"16.4", "16.6"}, b"L2198": {"15.10"}})

    def test_version_ranges_are_open_at_the_edge_of_what_was_recorded(self):
        everything = ["16.3", "16.4", "16.5", "16.6", "16.7", "17.6", "17.7", "17.9"]
        self.assertEqual(version_text({"16.4", "16.5", "16.6"}, everything), "16.4-16.6")
        self.assertEqual(version_text({"16.5"}, everything), "16.5")
        self.assertEqual(version_text({"17.6", "17.7"}, everything), "17.7 or earlier")
        self.assertEqual(version_text({"16.7"}, everything), "16.7 or later")
        self.assertEqual(version_text({"17.6", "17.7", "17.9"}, everything), "17.x")
        self.assertEqual(version_text({"16.4", "17.6"}, everything), "16.4, 17.6")

    def test_reported_ranges_are_checked_within_their_major_version(self):
        self.assertTrue(version_matches("16.4-16.6", "16.5"))
        self.assertFalse(version_matches("16.4-16.6", "16.7"))
        self.assertTrue(version_matches("16.4, 17.0", "17.0"))
        self.assertTrue(version_matches("17.9 or earlier", "17.2"))
        self.assertFalse(version_matches("17.9 or earlier", "16.6"))
        self.assertTrue(version_matches("18.6 or later", "18.7"))
        self.assertTrue(version_matches("17.x", "17.4"))
        self.assertFalse(version_matches("17.x", "18.0"))

    def test_table_signatures_read_the_version_and_fall_back_to_the_product(self):
        samples = [("16.4", self.pg_error(2145)), ("16.6", self.pg_error(2145)), ("15.10", self.pg_error(2198))]
        lines = table_lines(samples, [b"unrelated"], b"E")
        by_version = {version: pattern for pattern, version in lines}
        self.assertTrue(matches(by_version["16.x"], self.pg_error(2145)))
        self.assertIsNone(matches(by_version["16.x"], self.pg_error(2198)))
        self.assertTrue(matches(by_version[None], self.pg_error(9999)))

    def test_tag_names_become_versions(self):
        entry = {"versions": {"latest": "2.0.0"}}
        self.assertEqual(version_of(entry, "v1.25.1"), "1.25.1")
        self.assertEqual(version_of(entry, "7.2.4"), "7.2.4")
        self.assertEqual(version_of(entry, "latest"), "2.0.0")
        self.assertEqual(version_of(entry, "vanilla"), "vanilla")

    def test_context_stops_at_the_end_of_the_version_line(self):
        def info(version, next_line):
            return f"# Server\r\nvalkey_version:{version}\r\n{next_line}:x\r\n".encode()
        pattern = versioned_pattern([("8.0.2", info("8.0.2", "redis_git_sha1")), ("7.2.7", info("7.2.7", "redis_git_sha1"))])
        self.assertEqual(matches(pattern, info("8.1.0", "server_mode")).group(1), b"8.1.0")

    def test_binary_context_starts_at_the_field_name(self):
        def build(version, built):
            return (b"\x02buildDate\x00\x15\x00\x00\x00" + built.encode() + b"\x00\x02ferretdbVersion\x00\x08\x00\x00\x00v"
                    + version.encode() + b"\x00")
        pattern = versioned_pattern([("1.24.0", build("1.24.0", "2024-08-28T14:41:28Z")),
                                     ("1.23.1", build("1.23.1", "2024-07-30T10:22:18Z"))])
        self.assertEqual(matches(pattern, build("1.22.0", "2024-07-01T09:00:05Z")).group(1), b"1.22.0")

    def test_short_binary_greeting_uses_identifying_strings(self):
        def greeting(version, connection):
            body = b"\n" + version.encode() + b"\x00" + bytes([connection, 0, 0, 0]) + b"salt\x00caching_sha2_password\x00"
            return bytes([len(body), 0, 0, 0]) + body
        samples = [("26.7.0", greeting("26.7.0", 12)), ("9.7.4", greeting("9.7.4", 12))]
        self.assertIsNone(versioned_pattern(samples))
        pattern = versioned_pattern(samples, required=[b"caching_sha2_password"])
        self.assertEqual(matches(pattern, greeting("26.10.0", 40)).group(1), b"26.10.0")
        self.assertIsNone(matches(pattern, greeting("26.10.0", 40).replace(b"caching_sha2", b"mysql_native")))

    def test_the_reply_showing_the_version_is_used_when_several_ports_answer(self):
        def tag(version):
            return [{"protocol": "tcp", "probe": "Empty", "port": 33060, "response_hex": b"\x05\x00\x00\x00\x0b".hex()},
                    {"protocol": "tcp", "probe": "Empty", "port": 3306,
                     "response_hex": f"HELLO server {version}\r\n".encode().hex()}]
        evidence = {"1.2.3": tag("1.2.3"), "1.3.0": tag("1.3.0")}
        text = draft_signature({"image": "demo", "service": "demo", "product": "Demo"}, evidence)
        self.assertIn("server (", text)

    def test_too_little_context_is_refused(self):
        self.assertIsNone(versioned_pattern([("1.2", b"1.2"), ("1.3", b"1.3")]))
        self.assertIsNone(versioned_pattern([("1.2", b"no version here")]))

    def test_product_pattern_needs_the_name_and_two_tags(self):
        samples = [("1", b"+OK redis ready\r\nextra"), ("2", b"+OK redis ready\r\nother")]
        self.assertIsNotNone(product_pattern(samples, ["Redis"]))
        self.assertIsNone(product_pattern(samples, ["Postgres"]))
        self.assertIsNone(product_pattern(samples[:1], ["Redis"]))

    def test_product_pattern_keeps_only_the_naming_line(self):
        samples = [("1", b"HTTP/1.1 200 OK\r\nDate: Sat, 07 Nov\r\nServer: Caddy\r\n\r\n"),
                   ("2", b"HTTP/1.1 200 OK\r\nDate: Sat, 07 Nov\r\nServer: Caddy\r\n\r\nx")]
        pattern = product_pattern(samples, ["Caddy"])
        self.assertNotIn("Date", pattern)
        self.assertTrue(re.match(pattern.encode(), b"HTTP/1.1 404 Not Found\r\nDate: Mon\r\nServer: Caddy\r\n", re.S))

    def test_escape_never_emits_the_delimiter_or_regex_syntax(self):
        text = escape(b"a|b.c*(d)\\e[f]?+^$\x00\xff")
        self.assertNotIn("|", text)
        self.assertTrue(re.fullmatch(escape(b"a|b.c*(d)").encode(), b"a|b.c*(d)"))

    def test_draft_names_the_probe_and_versions(self):
        evidence = {
            "7.2.4": [{"protocol": "tcp", "probe": "RedisInfo", "response_hex": info("7.2.4", 3).hex()}],
            "6.2.14": [{"protocol": "tcp", "probe": "RedisInfo", "response_hex": info("6.2.14", 9).hex()}],
        }
        text = draft_signature(REDIS, evidence)
        self.assertIn("Signatures TCP RedisInfo\n", text)
        self.assertRegex(text, r"match redis m\|.+\|s p/Redis/ v/\$1/")

    def test_commonly_sent_probes_are_preferred(self):
        def reply(version):
            return f"HTTP/1.1 404 Not Found\r\nServer: nginx/{version}\r\n".encode().hex()

        probes = ("Rare", "Common", "Middle", "Other")
        evidence = {tag: [{"protocol": "tcp", "probe": p, "response_hex": reply(tag)} for p in probes]
                    for tag in ("1.2.3", "1.3.0")}
        rarities = {"Rare": 9, "Common": 1, "Middle": 4, "Other": 6}
        text = draft_signature({"image": "nginx", "service": "http", "product": "nginx"}, evidence, rarities)
        self.assertEqual(re.findall(r"Signatures TCP (\w+)", text), ["Common", "Middle", "Other"])

    def test_rarities_are_read_from_the_probe_file(self):
        text = "Probe TCP Empty q||\nProbe TCP A q|x|\nrarity 3\nProbe TCP B q|y|\n"
        self.assertEqual(probe_rarities(text), {"Empty": 0, "A": 3, "B": 5})


if __name__ == "__main__":
    unittest.main()
