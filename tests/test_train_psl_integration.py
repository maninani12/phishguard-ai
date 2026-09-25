"""Integration tests: train.py must use the PSL-aware splitter (no retraining)."""
import ast
import pathlib

import numpy as np
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from src import train as train_module
from src import domain_split
from src.domain_split import groups_for_urls, verify_group_overlap

TRAIN_PATH = pathlib.Path("src/train.py")


def _train_source():
    return TRAIN_PATH.read_text(encoding="utf-8")


def test_train_uses_authoritative_psl_splitter():
    # train.py must import the single authoritative implementation ...
    assert train_module.groups_for_urls is domain_split.groups_for_urls
    assert train_module.verify_group_overlap is domain_split.verify_group_overlap
    tree = ast.parse(_train_source())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "domain_split"
        and node.level == 1
        for alias in node.names
    }
    assert {"groups_for_urls", "verify_group_overlap"} <= imported
    # ... instead of duplicating registrable-domain extraction logic.
    assert "__import__('urllib.parse'" not in _train_source()
    assert 'split(".")[-' not in _train_source()


def test_train_grouping_matches_domain_split_on_canonical_shapes():
    urls = [
        "https://example.com/",
        "https://www.example.com/path",
        "https://login.example.com/a?x=1",
        "https://example.co.uk/",
        "https://www.example.co.uk:443/x",
        "HTTPS://LOGIN.EXAMPLE.COM./upper",
        "http://127.0.0.1:8080/t",
        "https://a.pages.dev/",
        "https://b.pages.dev/",
    ]
    assert groups_for_urls(urls) == train_module.groups_for_urls(urls)
    groups = groups_for_urls(urls)
    assert groups[0] == groups[1] == groups[2] == groups[5] == "example.com"
    assert groups[3] == groups[4] == "example.co.uk"
    assert groups[6] == "127.0.0.1"
    assert groups[7] != groups[8]


def test_domain_aware_split_has_zero_registrable_overlap():
    urls = [
        "https://example.com/",
        "https://www.example.com/path",
        "https://login.example.com/a",
        "https://example.co.uk/",
        "https://www.example.co.uk/x",
        "https://shop.example.co.uk/y",
        "https://other.test/",
        "https://www.other.test/y",
        "https://a.pages.dev/",
        "https://b.pages.dev/",
        "http://203.0.113.10/t",
        "http://203.0.113.10:8080/other",
    ]
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    groups = groups_for_urls(urls)
    # Same registrable domain (incl. subdomains, case, ports) stays in one group.
    assert groups[0] == groups[1] == groups[2]
    assert groups[3] == groups[4] == groups[5]
    assert groups[10] == groups[11] == "203.0.113.10"
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    tr, te = next(splitter.split(urls, y, groups=groups))
    report = verify_group_overlap([urls[i] for i in tr], [urls[i] for i in te])
    assert report["overlap_count"] == 0
    assert report["overlap_pct_of_union"] == 0.0


def test_primary_split_reproducible():
    idx = np.arange(1000)
    labels = np.array([0, 1] * 500)
    first = train_test_split(idx, test_size=0.2, random_state=42, stratify=labels)
    second = train_test_split(idx, test_size=0.2, random_state=42, stratify=labels)
    assert [a.tolist() for a in first] == [a.tolist() for a in second]


def test_domain_aware_split_reproducible():
    urls = [f"https://site{i:03d}.test/path" for i in range(60)]
    y = np.array([0, 1] * 30)
    groups = groups_for_urls(urls)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    first = next(splitter.split(urls, y, groups=groups))
    second = next(splitter.split(urls, y, groups=groups))
    assert [a.tolist() for a in first] == [a.tolist() for a in second]
    report = verify_group_overlap(
        [urls[i] for i in first[0]], [urls[i] for i in first[1]]
    )
    assert report["overlap_count"] == 0
