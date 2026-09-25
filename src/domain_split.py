"""Registrable-domain grouping with public-suffix awareness.

Uses the maintained ``tldextract`` dependency (Public Suffix List) instead of
manual TLD parsing. Evaluation-only helper: it does not train models and does
not modify datasets.

Grouping rule:
- ``example.com``, ``www.example.com``, ``login.example.com`` -> ``example.com``
- ``example.co.uk`` variants -> ``example.co.uk``
- Private-suffix tenants (e.g. ``a.pages.dev`` vs ``b.pages.dev``) stay
  separate because the extractor includes PSL private domains.
- IP hosts, single-label hosts, and unparseable inputs fall back to the
  lowercased hostname itself so every URL still yields a deterministic group.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Iterable, Sequence
from urllib.parse import urlsplit

import tldextract

_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True)


def _registered_domain(host: str) -> str:
    result = _EXTRACTOR(host)
    # ``top_domain_under_public_suffix`` is the maintained name;
    # ``registered_domain`` is its deprecated alias with identical behavior.
    try:
        value = result.top_domain_under_public_suffix
    except AttributeError:  # pragma: no cover - older tldextract fallback
        value = result.registered_domain
    return value or ""


@lru_cache(maxsize=131072)
def registrable_domain_from_host(host: str) -> str:
    """Return the registrable domain for a hostname string."""
    cleaned = (host or "").strip().removesuffix(".").lower()
    if not cleaned:
        return ""
    bare = cleaned.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return bare
    except ValueError:
        pass
    registered = _registered_domain(cleaned)
    return registered or cleaned


def registrable_domain_for_url(url: str) -> str:
    """Return the registrable domain for a URL string (no I/O)."""
    value = (url or "").strip()
    if not value:
        return ""
    hostname = urlsplit(value if "://" in value else "http://" + value).hostname or ""
    return registrable_domain_from_host(hostname)


def groups_for_urls(urls: Iterable[str]) -> list[str]:
    """Map each URL to its registrable-domain group."""
    return [registrable_domain_for_url(u) for u in urls]


def verify_group_overlap(
    train_urls: Sequence[str], test_urls: Sequence[str]
) -> dict:
    """Report registrable-domain overlap between two URL lists."""
    train_groups = set(groups_for_urls(train_urls))
    test_groups = set(groups_for_urls(test_urls))
    overlap = train_groups & test_groups
    union = train_groups | test_groups
    return {
        "train_groups": len(train_groups),
        "test_groups": len(test_groups),
        "overlap_count": len(overlap),
        "overlap_pct_of_union": (len(overlap) / len(union) * 100.0) if union else 0.0,
        "overlap_pct_of_test": (len(overlap) / len(test_groups) * 100.0) if test_groups else 0.0,
        "overlap_groups_sorted": sorted(overlap)[:25],
    }
