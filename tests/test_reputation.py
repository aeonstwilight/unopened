"""Reputation lookups with a fake transport: nothing here touches the network."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import parse_qs

import pytest

from unopened import pipeline, reputation
from unopened.analyzers import Options
from unopened.reputation import lookup_all

KEYS = {"ABUSECH_API_KEY": "mb-test-key", "VT_API_KEY": "vt-test-key"}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
UNKNOWN = "0" * 64


class FakeTransport:
    """Answers like the real APIs, from a table of {sha256: {"mb": ..., "vt": ...}}."""

    def __init__(self, answers=None, fail=None):
        self.answers = answers or {}
        self.fail = fail or {}
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        if "abuse.ch" in url:
            sha = parse_qs(body.decode())["hash"][0]
            if "mb" in self.fail:
                return self.fail["mb"]
            entry = self.answers.get(sha, {}).get("mb")
            if entry is None:
                return 200, json.dumps({"query_status": "hash_not_found"}).encode()
            return 200, json.dumps({"query_status": "ok", "data": [entry]}).encode()
        sha = url.rsplit("/", 1)[-1]
        if "vt" in self.fail:
            result = self.fail["vt"]
            if isinstance(result, Exception):
                raise result
            return result
        entry = self.answers.get(sha, {}).get("vt")
        if entry is None:
            return 404, json.dumps({"error": {"code": "NotFoundError"}}).encode()
        return 200, json.dumps({"data": {"attributes": entry}}).encode()


MB_EICAR = {"sha256_hash": EICAR_SHA256, "signature": "EICAR-Test", "tags": ["eicar", "test"],
            "first_seen": "2020-01-01 00:00:00", "file_type": "txt"}
VT_EICAR = {"last_analysis_stats": {"malicious": 60, "suspicious": 0, "undetected": 5},
            "popular_threat_classification": {"suggested_threat_label": "eicar/test"},
            "first_submission_date": 1_000_000_000, "meaningful_name": "eicar.com"}


def test_found_in_both():
    fake = FakeTransport({EICAR_SHA256: {"mb": MB_EICAR, "vt": VT_EICAR}})
    res = lookup_all([EICAR_SHA256], 20, send=fake, env=KEYS)[EICAR_SHA256]["sources"]
    assert res["malwarebazaar"]["status"] == "found"
    assert res["malwarebazaar"]["data"]["signature"] == "EICAR-Test"
    assert res["virustotal"]["data"]["malicious"] == 60
    assert res["virustotal"]["data"]["threat_label"] == "eicar/test"


def test_not_found_is_recorded_as_unknown():
    res = lookup_all([UNKNOWN], 20, send=FakeTransport(), env=KEYS)[UNKNOWN]["sources"]
    assert {r["status"] for r in res.values()} == {"not_found"}


def test_missing_keys_are_skipped_and_nothing_is_sent():
    fake = FakeTransport()
    res = lookup_all([UNKNOWN], 20, send=fake, env={})[UNKNOWN]["sources"]
    assert res["malwarebazaar"]["status"] == "skipped"
    assert "ABUSECH_API_KEY" in res["malwarebazaar"]["detail"]
    assert res["virustotal"]["status"] == "skipped"
    assert fake.calls == []


def test_only_the_hash_and_key_are_sent(make_file, fixtures):
    fake = FakeTransport()
    path = make_file("secret-name.exe", fixtures.benign_exe())
    report = pipeline.triage(path, Options(reputation=True), transport=fake, env=KEYS)
    sha = report.hashes["sha256"]
    content = path.read_bytes()
    assert len(fake.calls) == 2
    for call in fake.calls:
        assert call["url"].startswith("https://")
        sent = (call["url"] + json.dumps(call["headers"])).encode() + (call["body"] or b"")
        assert sha.encode() in sent
        assert b"secret-name" not in sent
        assert content[:64] not in sent
        assert len(call["body"] or b"") < 200
    mb = next(c for c in fake.calls if "abuse.ch" in c["url"])
    assert parse_qs(mb["body"].decode()) == {"query": ["get_info"], "hash": [sha]}
    assert mb["headers"]["Auth-Key"] == "mb-test-key"
    vt = next(c for c in fake.calls if "virustotal" in c["url"])
    assert vt["method"] == "GET" and vt["body"] is None
    assert vt["headers"]["x-apikey"] == "vt-test-key"


@pytest.mark.parametrize(("failure", "status", "detail"), [
    ((401, b"{}"), "error", "authentication"),
    ((429, b"{}"), "rate_limited", "quota"),
    ((500, b"oops"), "error", "unexpected"),
    (reputation.TransportError("timeout", "no answer within 10 seconds"), "error", "timeout"),
    (reputation.TransportError("network", "connection refused"), "error", "network"),
])
def test_virustotal_failures_are_recorded(failure, status, detail):
    res = lookup_all([UNKNOWN], 20, send=FakeTransport(fail={"vt": failure}), env=KEYS)
    vt = res[UNKNOWN]["sources"]["virustotal"]
    assert vt["status"] == status and detail in vt["detail"]
    assert res[UNKNOWN]["sources"]["malwarebazaar"]["status"] == "not_found"  # MB still asked


def test_rate_limit_stops_further_queries_to_that_source():
    other = "1" * 64
    fake = FakeTransport(fail={"vt": (429, b"{}")})
    res = lookup_all([UNKNOWN, other], 20, send=fake, env=KEYS)
    assert res[other]["sources"]["virustotal"]["status"] == "skipped"
    assert sum("virustotal" in c["url"] for c in fake.calls) == 1


def test_malwarebazaar_bad_key():
    fake = FakeTransport(fail={"mb": (200, b'{"query_status": "unknown_auth_key"}')})
    res = lookup_all([UNKNOWN], 20, send=fake, env=KEYS)
    assert "authentication" in res[UNKNOWN]["sources"]["malwarebazaar"]["detail"]


def test_lookup_limit():
    hashes = [f"{i:064x}" for i in range(5)]
    res = lookup_all(hashes, 2, send=FakeTransport(), env=KEYS)
    assert [bool(r.get("skipped")) for r in res.values()] == [False, False, True, True, True]


def test_invalid_hashes_are_never_sent():
    fake = FakeTransport()
    assert lookup_all(["not-a-hash", "abc"], 20, send=fake, env=KEYS) == {}
    assert fake.calls == []


def test_verdict_uses_reputation(make_file, fixtures):
    data = fixtures.EICAR
    sha = hashlib.sha256(data).hexdigest()
    fake = FakeTransport({sha: {"mb": MB_EICAR, "vt": VT_EICAR}})
    report = pipeline.triage(make_file("eicar.com", data), Options(reputation=True),
                             transport=fake, env=KEYS)
    assert report.verdict["rule"] == "V-REP-01"
    assert [r["rule"] for r in report.verdict["reasons"]][:2] == ["V-REP-01", "V-REP-02"]


def test_member_reputation_reaches_the_container(make_file, arch_fx):
    inner = b"fixture member known to the fake MalwareBazaar"
    sha = hashlib.sha256(inner).hexdigest()
    fake = FakeTransport({sha: {"mb": dict(MB_EICAR, sha256_hash=sha)}})
    path = make_file("a.zip", arch_fx.zip_plain({"x.txt": inner}))
    report = pipeline.triage(path, Options(reputation=True), transport=fake,
                             env={"ABUSECH_API_KEY": "k"})
    child = report.children[0]["report"]
    assert child.verdict["rule"] == "V-REP-01"
    assert report.verdict["rule"] == "V-MAL-09"


def test_reputation_off_is_listed_under_not_checked(make_file, fixtures):
    report = pipeline.triage(make_file("a.exe", fixtures.benign_exe()), Options(),
                             isolate=False)
    assert report.reputation is None
    assert any(n.check == "Hash reputation lookup" and "--reputation" in n.reason
               for n in report.not_checked)


def test_reputation_on_but_unanswered_lowers_confidence(make_file):
    report = pipeline.triage(make_file("a.txt", b"plain words only here\n"),
                             Options(reputation=True), transport=FakeTransport(), env={})
    assert report.verdict["value"] == "no findings"
    assert report.verdict["confidence"] == "low"
    assert any("Reputation: virustotal" == n.check for n in report.not_checked)


def test_reputation_in_reports(make_file, fixtures):
    from unopened.report import json_report, markdown

    data = fixtures.EICAR
    sha = hashlib.sha256(data).hexdigest()
    fake = FakeTransport({sha: {"mb": MB_EICAR, "vt": VT_EICAR}})
    report = pipeline.triage(make_file("eicar.com", data), Options(reputation=True),
                             transport=fake, env=KEYS)
    md = markdown.render(report)
    assert "## Reputation" in md and "only the SHA256 was sent" in md
    assert "60 malicious" in md and "`EICAR-Test`" in md
    doc = json.loads(json_report.render(report))
    assert doc["reputation"]["sources"]["virustotal"]["data"]["malicious"] == 60
