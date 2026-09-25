import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from src.domain_split import (
    groups_for_urls,
    registrable_domain_for_url,
    registrable_domain_from_host,
    verify_group_overlap,
)


def test_common_domains_share_registrable_domain():
    assert registrable_domain_from_host("example.com") == "example.com"
    assert registrable_domain_from_host("www.example.com") == "example.com"
    assert registrable_domain_from_host("login.example.com") == "example.com"
    assert registrable_domain_for_url("https://login.example.com/path?q=1") == "example.com"


def test_multi_level_public_suffix():
    assert registrable_domain_from_host("example.co.uk") == "example.co.uk"
    assert registrable_domain_from_host("www.example.co.uk") == "example.co.uk"
    assert registrable_domain_from_host("login.example.co.uk") == "example.co.uk"


def test_private_suffix_tenants_stay_separate():
    assert registrable_domain_from_host("a.pages.dev") == "a.pages.dev"
    assert registrable_domain_from_host("b.pages.dev") == "b.pages.dev"
    assert registrable_domain_from_host("a.pages.dev") != registrable_domain_from_host("b.pages.dev")


def test_case_port_trailing_dot_and_idna():
    assert registrable_domain_for_url("HTTPS://WWW.Example.COM./path") == "example.com"
    assert registrable_domain_for_url("https://www.example.com:443/") == "example.com"
    assert registrable_domain_for_url("http://www.example.com:8080/x") == "example.com"
    # Punycode host is grouped under its ASCII registrable domain.
    assert registrable_domain_from_host("xn--nxasmq6b.example.com") != ""


def test_ip_and_single_label_fallback():
    assert registrable_domain_for_url("http://127.0.0.1/test") == "127.0.0.1"
    assert registrable_domain_for_url("http://203.0.113.10:8080/x") == "203.0.113.10"
    assert registrable_domain_from_host("localhost") == "localhost"
    assert registrable_domain_for_url("") == ""
    assert registrable_domain_from_host("") == ""


def test_group_split_has_zero_registrable_overlap():
    urls = [
        "https://example.com/",
        "https://www.example.com/path",
        "https://login.example.com/a",
        "https://example.co.uk/",
        "https://www.example.co.uk/x",
        "https://other.test/",
        "https://www.other.test/y",
        "https://a.pages.dev/",
        "https://b.pages.dev/",
        "http://127.0.0.1/t",
    ]
    groups = groups_for_urls(urls)
    assert groups[0] == groups[1] == groups[2] == "example.com"
    assert groups[3] == groups[4] == "example.co.uk"
    assert groups[7] != groups[8]

    y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
    train_idx, test_idx = next(splitter.split(urls, y, groups=groups))
    report = verify_group_overlap(
        [urls[i] for i in train_idx], [urls[i] for i in test_idx]
    )
    assert report["overlap_count"] == 0
    assert report["overlap_pct_of_union"] == 0.0
    assert report["train_groups"] > 0 and report["test_groups"] > 0


def test_verify_group_overlap_reports_counts():
    report = verify_group_overlap(
        ["https://example.com/", "https://other.test/"],
        ["https://www.example.com/x", "https://fresh.test/"],
    )
    assert report["train_groups"] == 2
    assert report["test_groups"] == 2
    assert report["overlap_count"] == 1  # example.com shared
    assert report["overlap_pct_of_test"] == 50.0
    assert "example.com" in report["overlap_groups_sorted"]


def test_no_manual_tld_parsing_in_module():
    import pathlib

    text = pathlib.Path("src/domain_split.py").read_text(encoding="utf-8")
    assert "tldextract" in text
    # Guard against reintroducing naive suffix splitting as the grouping rule.
    assert 'split(".")[-' not in text
