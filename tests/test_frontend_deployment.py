"""Frontend deployment-configuration guardrails.

These tests read the frontend source and the production build output. They assert
that a production bundle can never point the browser at localhost, which would
silently break the deployed site.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
API_JS = FRONTEND / "src" / "api.js"
DIST = FRONTEND / "dist"


def test_api_module_exposes_the_existing_contract():
    text = API_JS.read_text(encoding="utf-8")
    for symbol in ("API_BASE_URL", "API_CONFIGURED", "API_NOT_CONFIGURED_MESSAGE", "apiFetch"):
        assert symbol in text


def test_api_module_guards_loopback_in_production():
    text = API_JS.read_text(encoding="utf-8")
    assert "LOOPBACK" in text
    assert "import.meta.env.DEV" in text
    # The loopback value must be gated behind the dev check, not used unconditionally.
    assert re.search(r"LOOPBACK\.test\(configured\)\s*&&\s*!isDev", text)


def test_no_hardcoded_production_api_url_in_source():
    """The network layer must not pin a deployed API host.

    Only files that actually perform a request are inspected, so UI placeholder
    text such as ``https://example.com`` in an input hint is not a violation.
    A loopback default is permitted only behind an ``import.meta.env.DEV`` guard.
    """
    sources = sorted((FRONTEND / "src").rglob("*.js")) + sorted((FRONTEND / "src").rglob("*.jsx"))
    network_files = [p for p in sources if "fetch(" in p.read_text(encoding="utf-8")]
    assert network_files, "expected at least one frontend module to perform requests"
    for path in network_files:
        text = path.read_text(encoding="utf-8")
        dev_gated = "import.meta.env.DEV" in text
        for match in re.findall(r"https?://[A-Za-z0-9.\-]+(?::\d+)?", text):
            if "127.0.0.1" in match or "localhost" in match:
                assert dev_gated, f"{path.name} hardcodes loopback {match} outside a dev guard"
            else:
                raise AssertionError(f"{path.name} pins a production host: {match}")


def test_env_example_documents_production_usage():
    text = (FRONTEND / ".env.example").read_text(encoding="utf-8")
    assert "VITE_API_BASE_URL" in text
    assert "VITE_API_BASE_URL" in text
    assert "localhost" in text.lower() or "127.0.0.1" in text
    assert "onrender.com" in text, "must document the expected production base URL shape"
    assert "secret" in text.lower()


@pytest.mark.skipif(not (DIST / "index.html").exists(),
                    reason="frontend/dist not built; run `npm run build` in frontend/")
def test_production_build_never_uses_loopback_as_the_api_base():
    """Even when a local .env.local leaks localhost into the build, it must be rejected."""
    bundles = list((DIST / "assets").glob("*.js"))
    assert bundles, "no built JS assets found"
    # Minification re-escapes the regex, so compare against a de-escaped copy.
    joined = "\n".join(b.read_text(encoding="utf-8") for b in bundles)
    flat = joined.replace("\\", "")

    # The loopback guard must be present in the compiled output...
    assert "127.0.0.1|localhost" in flat, "loopback guard missing from production bundle"
    # ...and no request URL may ever be emitted against a loopback host.
    assert "http://127.0.0.1:8013/api" not in flat, "bundle emits a loopback API request URL"
    assert "http://localhost/api" not in flat, "bundle emits a loopback API request URL"

    # The API fetch must be a single call site against the resolved base.
    fetch_calls = re.findall(r"fetch\(`\$\{[^}]+\}(/api/[A-Za-z0-9/_-]*)", flat)
    assert fetch_calls, "could not locate the API fetch call in the bundle"


@pytest.mark.skipif(not (DIST / "index.html").exists(),
                    reason="frontend/dist not built; run `npm run build` in frontend/")
def test_production_build_uses_the_github_pages_base_path():
    html = (DIST / "index.html").read_text(encoding="utf-8")
    assert "/phishguard-ai/" in html
    for asset in re.findall(r'(?:src|href)="([^"]+)"', html):
        if asset.startswith(("http", "//", "data:")):
            continue
        assert asset.startswith("/phishguard-ai/"), f"asset is not under the Pages base path: {asset}"


@pytest.mark.skipif(not (DIST / "index.html").exists(),
                    reason="frontend/dist not built; run `npm run build` in frontend/")
def test_production_build_contains_the_agent_endpoint_and_notice():
    bundles = list((DIST / "assets").glob("*.js"))
    joined = "\n".join(b.read_text(encoding="utf-8") for b in bundles)
    assert "/api/agent/analyze" in joined
    assert "/api/predict" in joined
    assert "RESEARCH" in joined.upper()
    assert "apex" in joined.lower()
