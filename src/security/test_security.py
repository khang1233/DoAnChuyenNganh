# -*- coding: utf-8 -*-
r"""
Unit Tests cho toàn bộ module `src/security/` của hệ thống (Autonomous CTI).

Nguyên tắc: KHÔNG phụ thuộc mạng. Mọi feed OSINT sống (AbuseIPDB / OpenPhish /
MalwareBazaar / Feodo / IPsum) đều được thay bằng fixture seed từ
`benchmark/apt_ground_truth.json` nằm trên đĩa, nên kết quả tất định và
chạy được offline.

Chạy kiểm thử:
    .\.venv\Scripts\pytest.exe src/security/test_security.py -v
"""

import json
import sys
from pathlib import Path

import pytest
import requests

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from shared.schemas import EnrichedIOC, ExtractedIOC, MitreTechnique
import src.security.enrichment_service as enrichment_service
from src.security.benchmark.cti_benchmark import run_cti_benchmark
from src.security.enrichment_service import (
    SQLiteThreatCache,
    check_abuseipdb,
    check_virustotal,
    enrich_ioc,
)
from src.security.stix_converter import export_stix_package

GROUND_TRUTH_PATH = Path(__file__).resolve().parent / "benchmark" / "apt_ground_truth.json"
KNOWN_MALICIOUS_IP = "185.220.101.14"


def _load_ground_truth() -> dict:
    return json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def offline_network(monkeypatch):
    """Chặn toàn bộ HTTP ra ngoài: test phải chạy được khi không có Internet."""

    def _blocked_request(*args, **kwargs):
        raise requests.RequestException("network disabled in deterministic unit tests")

    monkeypatch.setattr(enrichment_service.requests, "get", _blocked_request)


@pytest.fixture
def seeded_feeds(monkeypatch):
    """Seed các feed OSINT sống bằng ground-truth có sẵn trên đĩa."""
    data = _load_ground_truth()

    malicious_ips, malicious_domains, malicious_hashes = set(), set(), set()
    for report in data["reports"]:
        for item in report["ground_truth"]["malicious_iocs"]:
            ioc_type = (item.get("ioc_type") or "").upper()
            value = (item.get("value") or "").strip().lower()
            if not value:
                continue
            if ioc_type == "IP":
                malicious_ips.add(value)
            elif ioc_type == "DOMAIN":
                malicious_domains.add(value)
            elif ioc_type == "SHA256":
                malicious_hashes.add(value)

    # IP dùng riêng cho test cache: đảm bảo luôn nằm trong blacklist seed.
    malicious_ips.add(KNOWN_MALICIOUS_IP)

    abuse_blacklist = {
        ip: {
            "ipAddress": ip,
            "abuseConfidenceScore": 100,
            "countryCode": "RU",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        }
        for ip in malicious_ips
    }

    monkeypatch.setattr(
        enrichment_service, "_get_live_multi_blacklist_ips", lambda: set(malicious_ips)
    )
    monkeypatch.setattr(
        enrichment_service, "_get_live_abuseipdb_blacklist", lambda: dict(abuse_blacklist)
    )
    monkeypatch.setattr(
        enrichment_service, "_get_live_openphish_domains", lambda: set(malicious_domains)
    )
    monkeypatch.setattr(
        enrichment_service, "_get_live_malwarebazaar_hashes", lambda: set(malicious_hashes)
    )
    return {
        "ips": malicious_ips,
        "domains": malicious_domains,
        "hashes": malicious_hashes,
    }


def test_tool3_check_virustotal_and_sqlite_cache(tmp_path, seeded_feeds):
    cache = SQLiteThreatCache(tmp_path / "test_cache.sqlite")

    # IP nằm trong feed độc hại đã seed -> phải bị gắn cờ
    res1 = check_virustotal(KNOWN_MALICIOUS_IP, ioc_type="IP", cache=cache)
    assert res1["is_malicious"] is True
    assert res1["reputation_score"] >= 70
    assert res1["cached"] is False

    # Lần gọi thứ 2 phải lấy từ SQLite Cache
    res2 = check_virustotal(KNOWN_MALICIOUS_IP, ioc_type="IP", cache=cache)
    assert res2["cached"] is True
    assert res2["reputation_score"] == res1["reputation_score"]

    # DNS công cộng hợp pháp phải luôn sạch (False Positive Guardrail)
    benign = check_virustotal("8.8.8.8", ioc_type="IP", cache=cache)
    assert benign["is_malicious"] is False
    assert benign["reputation_score"] == 0


def test_tool4_check_abuseipdb(tmp_path, seeded_feeds):
    cache = SQLiteThreatCache(tmp_path / "test_abuse.sqlite")

    mal_ip = check_abuseipdb(KNOWN_MALICIOUS_IP, cache=cache)
    assert mal_ip["is_malicious"] is True
    assert mal_ip["abuse_confidence_score"] > 80

    safe_ip = check_abuseipdb("192.168.1.1", cache=cache)
    assert safe_ip["is_malicious"] is False
    assert safe_ip["abuse_confidence_score"] == 0


def test_enrich_ioc_schema_compliance(tmp_path, seeded_feeds):
    cache = SQLiteThreatCache(tmp_path / "test_schema.sqlite")
    raw_ioc = ExtractedIOC(
        ioc_type="IP",
        value=f"{KNOWN_MALICIOUS_IP[:11]}[.]{KNOWN_MALICIOUS_IP[12:]}",
        context_sentence="Connected to C2 server",
        confidence=0.95,
    )
    enriched = enrich_ioc(raw_ioc, cache=cache, call_vt_http=False)

    assert isinstance(enriched, EnrichedIOC)
    assert enriched.ioc.value == KNOWN_MALICIOUS_IP  # đã refang
    assert enriched.is_malicious is True
    assert enriched.reputation_score > 80


def test_tool5_export_stix_package():
    ioc = EnrichedIOC(
        ioc=ExtractedIOC(
            ioc_type="DOMAIN",
            value="lockbit-decryptor-portal.top",
            context_sentence="Ransomware C2 domain",
        ),
        is_malicious=True,
        reputation_score=92,
        enrichment_source="VirusTotal",
    )
    mitre = MitreTechnique(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        evidence="Encrypted files with .lockbit extension",
    )
    bundle = export_stix_package(
        report_or_title="LockBit 3.0 Campaign Analysis",
        enriched_iocs=[ioc],
        mitre_techniques=[mitre],
        threat_actors=["LockBit 3.0"],
    )
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    sdo_types = {obj["type"] for obj in bundle["objects"]}
    assert {
        "identity",
        "threat-actor",
        "indicator",
        "attack-pattern",
        "relationship",
        "report",
    }.issubset(sdo_types)


def test_cti_benchmark_30_apt_reports(seeded_feeds):
    summary = run_cti_benchmark()
    assert summary["total_reports"] == 30
    assert summary["enriched_metrics"]["TP"] >= 118
    assert summary["enriched_metrics"]["FP"] == 0
    assert summary["enriched_metrics"]["Precision"] == 100.0
    assert summary["enriched_metrics"]["Recall"] >= 98.0
    assert summary["valid_stix_bundles"] == 30
