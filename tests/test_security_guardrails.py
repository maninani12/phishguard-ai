"""Security guardrail tests for the PhishGuard agent and API.

The agent must never fetch, resolve, render or execute anything related to a
submitted URL. These tests fail if a network-capable or code-execution import
ever appears in the request path.
"""
import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The only network destination the frontend is permitted to contact is the
# configured PhishGuard API. That is a browser fetch to our own backend, not a
# fetch of the submitted URL, so it is explicitly allowed.
FORBIDDEN_CALLS = {
    "requests", "httpx", "urllib3", "aiohttp", "pycurl", "http.client",
    "socket", "ssl", "ftplib", "telnetlib", "smtplib", "asyncio",
    "selenium", "playwright", "pyppeteer",
    "subprocess", "multiprocessing", "ctypes",
}
FORBIDDEN_ATTRS = {"system", "popen", "spawn", "fork", "execv", "execve", "spawnl"}
BANNED_NAMES = {"eval", "exec", "compile", "__import__", "getattr", "setattr"}

AGENT_PACKAGE = [ROOT / "backend" / "agent" / "__init__.py",
                 ROOT / "backend" / "agent" / "agent.py",
                 ROOT / "backend" / "agent" / "explanation.py",
                 ROOT / "backend" / "agent" / "schemas.py"]
REQUEST_PATH = AGENT_PACKAGE + [ROOT / "backend" / "app.py", ROOT / "backend" / "prediction.py"]

FRONTEND_SRC = sorted((ROOT / "frontend" / "src").rglob("*.js")) + \
               sorted((ROOT / "frontend" / "src").rglob("*.jsx"))


def imported_roots(path: pathlib.Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.module:      # relative import inside the project
                continue
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("path", REQUEST_PATH, ids=lambda p: p.name)
def test_request_path_imports_nothing_network_or_executable(path):
    offenders = imported_roots(path) & FORBIDDEN_CALLS
    assert not offenders, f"{path.name} imports network/exec modules: {sorted(offenders)}"


@pytest.mark.parametrize("path", REQUEST_PATH, ids=lambda p: p.name)
def test_request_path_never_calls_forbidden_builtins(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in BANNED_NAMES:
                raise AssertionError(f"{path.name} calls {func.id}() at line {node.lineno}")
            if isinstance(func, ast.Attribute) and func.attr in FORBIDDEN_ATTRS:
                raise AssertionError(f"{path.name} calls .{func.attr}() at line {node.lineno}")


def executable_source(path: pathlib.Path) -> str:
    """Source text with comments and string literals removed.

    Docstrings legitimately *name* the forbidden modules in order to declare that
    they are not used, so a raw text scan would produce false positives. This
    returns only the code that actually executes.
    """
    import io
    import tokenize
    kept = []
    with open(path, "rb") as handle:
        for token in tokenize.tokenize(handle.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            kept.append(token.string)
    return " ".join(kept)


def test_agent_source_has_no_outbound_client():
    """Scans executable code only, so the safety docstrings do not trip the check."""
    for path in AGENT_PACKAGE + [ROOT / "backend" / "app.py", ROOT / "backend" / "prediction.py"]:
        code = executable_source(path).lower()
        for needle in ("requests.get", "requests.post", "urlopen", "urllib.request",
                       "httpx", "socket.", "selenium", "playwright", "subprocess",
                       "os.system", "urlretrieve", "webbrowser", "aiohttp"):
            assert needle not in code, f"{path.name} uses {needle} in executable code"


def test_agent_is_deterministic():
    from backend.agent import analyze_url
    first = analyze_url("http://192.0.2.5:8080/login?next=%2Fadmin").model_dump()
    second = analyze_url("http://192.0.2.5:8080/login?next=%2Fadmin").model_dump()
    assert first == second


def test_no_external_llm_dependency():
    """No API-key-based or local-model-server integration may be introduced."""
    forbidden = ("openai", "anthropic", "ollama", "langchain", "llamaindex",
                 "google.generativeai", "cohere", "mistralai", "huggingface_hub",
                 "replicate", "groq")
    for path in REQUEST_PATH:
        roots = {name.lower() for name in imported_roots(path)}
        assert not roots & set(forbidden), f"{path.name} imports an LLM dependency"
    for name in ("openai", "anthropic", "ollama", "langchain"):
        assert name not in (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()


def test_frontend_only_fetches_the_configured_api():
    """The browser may call our own API, and nothing else."""
    for path in FRONTEND_SRC:
        text = path.read_text(encoding="utf-8")
        for needle in ("XMLHttpRequest", "axios", "navigator.sendBeacon",
                       "new WebSocket", "EventSource", "window.open", "location.href"):
            assert needle not in text, f"{path.name} references {needle}"


def test_cors_origins_remain_restricted():
    from backend.app import app
    origins = set()
    for middleware in app.user_middleware:
        if middleware.cls.__name__ == "CORSMiddleware":
            options = middleware.kwargs
            origins = set(options.get("allow_origins") or [])
    assert origins == {"https://maninani12.github.io",
                       "http://localhost:5173",
                       "http://127.0.0.1:5173"}


def test_url_limit_and_scheme_allowlist_enforced():
    from backend.prediction import MAX_URL_LENGTH, validate_url_text
    assert MAX_URL_LENGTH == 2048
    with pytest.raises(ValueError):
        validate_url_text("https://example.com/" + "a" * MAX_URL_LENGTH)
    with pytest.raises(ValueError):
        validate_url_text("ftp://example.com/")
    with pytest.raises(ValueError):
        validate_url_text("https://example.com/\x00")


def test_no_secrets_in_tracked_source():
    """Match real credential shapes, not incidental substrings such as 'risk-text'."""
    import re
    patterns = (
        r"\bsk-[A-Za-z0-9]{16,}",          # OpenAI-style key
        r"\bghp_[A-Za-z0-9]{20,}",         # GitHub personal access token
        r"\bgithub_pat_[A-Za-z0-9_]{20,}",
        r"\bAKIA[0-9A-Z]{12,}",            # AWS access key id
        r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
        r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*['\"][^'\"]{8,}",
    )
    for path in REQUEST_PATH + FRONTEND_SRC + [ROOT / "frontend" / ".env.example",
                                               ROOT / "render.yaml", ROOT / "requirements.txt"]:
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            match = re.search(pattern, text)
            assert match is None, f"{path.name} contains a secret-like value: {match.group(0)[:24]}"
