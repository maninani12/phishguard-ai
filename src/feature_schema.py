"""Authoritative URL-only feature schema and safe normalization."""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

FEATURES = [
    "URLLength", "DomainLength", "TLDLength", "TLD", "NoOfSubDomain",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsDomainIP", "IsHTTPS",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes", "num_at", "num_hashes",
    "num_percent", "num_colons", "num_semicolons", "url_entropy", "path_length",
    "query_length", "fragment_length", "has_port", "has_punycode", "has_url_shortener",
    "num_encoded_chars", "max_repeat_ratio", "num_suspicious_keywords",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"}
KEYWORDS = ("login", "verify", "account", "secure", "update", "password", "signin", "bank", "confirm", "wallet", "support", "recover", "auth", "billing")
OBFUSCATED = set("@%\\")

def normalize_url(url: str) -> str:
    """Normalize only URL syntax; preserve path, query, fragments and subdomains."""
    value = url.strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        value = "http://" + value
    p = urlsplit(value)
    scheme = p.scheme.lower()
    host = (p.hostname or "").removesuffix(".").lower()
    if not host:
        raise ValueError("URL must include a hostname")
    try:
        ipaddress.ip_address(host.strip("[]"))
        host = f"[{host.strip('[]')}]" if ":" in host else host
    except ValueError:
        labels=host.split(".")
        try: ascii_labels=[label.encode("idna").decode("ascii") for label in labels]
        except UnicodeError as exc: raise ValueError("URL contains an invalid hostname") from exc
        if len(".".join(ascii_labels))>253 or any(not label or len(label)>63 or not re.fullmatch(r"[a-z0-9_-]+",label) for label in ascii_labels):
            raise ValueError("URL contains an invalid hostname")
        if any(c.isspace() for c in host):
            raise ValueError("URL contains whitespace in the hostname")
    userinfo = ""
    if "@" in p.netloc:
        userinfo = p.netloc.rsplit("@", 1)[0] + "@"
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    port_text = f":{port}" if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)) else ""
    path = p.path or "/"
    return urlunsplit((scheme, userinfo + host + port_text, path, p.query, p.fragment))

def extract_url_features(url: str) -> dict:
    """Extract reproducible features from the URL string only. Never performs I/O."""
    value = normalize_url(url)
    p = urlsplit(value)
    host = (p.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    hostparts = host.split(".") if host else []
    tld = hostparts[-1] if len(hostparts) > 1 else ""
    chars = Counter(value)
    n = max(len(value), 1)
    letters = sum(c.isalpha() for c in value)
    digits = sum(c.isdigit() for c in value)
    special = sum(not c.isalnum() for c in value)
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", value))
    entropy = -sum((count / n) * math.log2(count / n) for count in chars.values())
    repeated = max(chars.values(), default=0) / n
    obf = sum(value.count(c) for c in OBFUSCATED)
    try:
        port = p.port
    except ValueError:
        port = None
    suspicious = sum(1 for k in KEYWORDS if k in value.lower())
    other_special = sum(value.count(c) for c in "~!*'();:@&=+$,/?#[]{}|\\^%")
    return {
        "URLLength": len(value), "DomainLength": len(host), "TLDLength": len(tld), "TLD": tld,
        "NoOfSubDomain": max(len(hostparts) - 2, 0), "HasObfuscation": int(obf > 0),
        "NoOfObfuscatedChar": obf, "ObfuscationRatio": obf / n, "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / n, "NoOfDegitsInURL": digits, "DegitRatioInURL": digits / n,
        "NoOfEqualsInURL": value.count("="), "NoOfQMarkInURL": value.count("?"),
        "NoOfAmpersandInURL": value.count("&"), "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": special / n, "IsDomainIP": is_ip, "IsHTTPS": int(p.scheme == "https"),
        "num_dots": value.count("."), "num_hyphens": value.count("-"), "num_underscores": value.count("_"),
        "num_slashes": value.count("/"), "num_at": value.count("@"), "num_hashes": value.count("#"),
        "num_percent": value.count("%"), "num_colons": value.count(":"), "num_semicolons": value.count(";"),
        "url_entropy": entropy, "path_length": len(p.path), "query_length": len(p.query),
        "fragment_length": len(p.fragment), "has_port": int(port is not None),
        "has_punycode": int(any(part.startswith("xn--") for part in hostparts)),
        "has_url_shortener": int(host in SHORTENERS), "num_encoded_chars": encoded,
        "max_repeat_ratio": repeated, "num_suspicious_keywords": suspicious,
    }
