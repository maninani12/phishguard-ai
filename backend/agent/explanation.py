"""Deterministic explanation layer for the PhishGuard agent.

Turns the 38 measured URL features into human-readable observations. It is
rule-based and fully explainable: every statement is derived from a feature that
was actually computed from the submitted URL string.

Two rules are enforced here:

1. A signal is only reported when it is actually present in the features.
2. No claim is ever made about the *website*. The submitted URL is never
   visited, so nothing is known about the page, its owner, or its content.
"""
from urllib.parse import urlsplit

from src.domain_split import registrable_domain_from_host
from src.feature_schema import KEYWORDS

PREDICTION_LEGITIMATE = "Legitimate"
PREDICTION_PHISHING = "Potential Phishing"

CONFIDENCE_SEMANTICS = (
    "Classifier score for the class it predicted, produced by the trained model's "
    "predict_proba. It is not a calibrated probability that a URL is malicious, "
    "and it has not been calibrated on held-out real-world traffic."
)

DISCLAIMER = (
    "PhishGuard analyzes URL-level characteristics only. The submitted website is "
    "never visited, fetched or rendered, so nothing is known about the page content "
    "or its owner. A prediction is a statistical classification, not a safety "
    "guarantee, and it can be wrong in both directions."
)

RESEARCH_NOTICE = (
    "Research / demonstration system. The model is trained on the UCI PhiUSIIL "
    "corpus, whose legitimate class contains only HTTPS, www-prefixed, root-path "
    "URLs. Legitimate apex, non-www subdomain, HTTP and query-string URLs are "
    "absent from the training data, so the model's verdict on those shapes is "
    "unreliable and tends to over-report phishing."
)

# Shapes that are absent from, or heavily underrepresented in, the training corpus.
# This is a measured property of the dataset, not a guess.
TRAINING_DISTRIBUTION_GAPS = {
    "http_scheme": "Plain HTTP (the corpus contains no legitimate HTTP URLs at all)",
    "apex_host": "A bare apex host with no www prefix",
    "subdomain_host": "A non-www subdomain host",
    "query_string": "A URL carrying a query string",
    "path_component": "A URL with a path component (every legitimate training URL is a bare root path)",
    "long_path": "A URL with a long path",
}


def _shape_flags(normalized_url: str) -> dict:
    parsed = urlsplit(normalized_url)
    host = parsed.hostname or ""
    registrable = registrable_domain_from_host(host) if host else ""
    is_www = host.startswith("www.")
    return {
        "scheme": parsed.scheme,
        "host": host,
        "registrable": registrable,
        "is_www": is_www,
        "is_apex": bool(host) and bool(registrable) and host == registrable and not is_www,
        "is_subdomain": bool(host) and bool(registrable) and host != registrable and not is_www,
        "has_query": bool(parsed.query),
        "path_length": len(parsed.path),
        "normalized_url": normalized_url,
    }


def _signal(code, label, value, observation, risk_relevant=True):
    return {"code": code, "label": label, "value": value,
            "observation": observation, "risk_relevant": risk_relevant}


def build_signals(features: dict, normalized_url: str) -> list:
    """Return observations for features that are actually present."""
    flags = _shape_flags(normalized_url)
    signals = []

    if features.get("IsDomainIP") == 1:
        signals.append(_signal(
            "ip_host", "IP address host", features["IsDomainIP"],
            f"The host is the raw IP address {flags['host']} rather than a named domain."))

    if features.get("IsHTTPS") == 0:
        signals.append(_signal(
            "no_https", "No HTTPS", features["IsHTTPS"],
            "The URL does not use HTTPS, so the connection would not be encrypted."))

    if features.get("has_port") == 1:
        signals.append(_signal(
            "custom_port", "Non-default port", features["has_port"],
            f"The URL specifies an explicit port ({flags['host']})."))

    if features.get("has_punycode") == 1:
        signals.append(_signal(
            "punycode", "Punycode host", features["has_punycode"],
            "The host contains punycode (xn--) labels, which encode non-Latin characters."))

    if features.get("has_url_shortener") == 1:
        signals.append(_signal(
            "shortener", "Known URL shortener", features["has_url_shortener"],
            f"The host matches a known URL-shortener service ({flags['host']})."))

    encoded = int(features.get("num_encoded_chars") or 0)
    if encoded > 0:
        signals.append(_signal(
            "encoded_chars", "Percent-encoded characters", encoded,
            f"The URL contains {encoded} percent-encoded character(s)."))

    keywords = int(features.get("num_suspicious_keywords") or 0)
    if keywords > 0:
        present = [k for k in KEYWORDS if k in normalized_url.lower()]
        shown = ", ".join(present[:5])
        signals.append(_signal(
            "suspicious_keywords", "Phishing-related keywords", keywords,
            f"The URL contains {keywords} keyword(s) the model tracks as phishing-related "
            f"({shown})."))

    at_count = int(features.get("num_at") or 0)
    if at_count > 0:
        signals.append(_signal(
            "at_sign", "'@' in URL", at_count,
            "The URL contains an '@' character, which can be used to disguise the real host."))

    if int(features.get("HasObfuscation") or 0) == 1:
        signals.append(_signal(
            "obfuscation", "Obfuscation characters", features["HasObfuscation"],
            "The URL contains characters commonly used to obfuscate a link ('@', '%' or a backslash)."))

    if flags["has_query"]:
        signals.append(_signal(
            "query_string", "Query string present", len(urlsplit(normalized_url).query),
            "The URL carries query parameters, which are commonly used to pass a "
            "redirect target or tracking identifier."))

    fragment = int(features.get("fragment_length") or 0)
    if fragment > 0:
        signals.append(_signal(
            "fragment", "Fragment present", fragment,
            "The URL contains a fragment component after '#'."))

    subs = int(features.get("NoOfSubDomain") or 0)
    if subs >= 3:
        signals.append(_signal(
            "deep_subdomains", "Many subdomain labels", subs,
            f"The host uses {subs} subdomain labels, which is deeper than typical."))

    length = int(features.get("URLLength") or 0)
    if length >= 100:
        signals.append(_signal(
            "long_url", "Long URL", length,
            f"The URL is {length} characters long."))

    path_length = int(features.get("path_length") or 0)
    if path_length >= 40:
        signals.append(_signal(
            "long_path", "Long path", path_length,
            f"The path component is {path_length} characters long."))

    repeat = float(features.get("max_repeat_ratio") or 0.0)
    if repeat >= 0.2:
        signals.append(_signal(
            "character_repetition", "Repeated characters", round(repeat, 3),
            f"One character makes up {round(repeat * 100, 1)}% of the URL."))

    return signals


def distribution_gaps(features: dict, normalized_url: str) -> list:
    """Shapes where the training corpus has no or very few legitimate examples."""
    flags = _shape_flags(normalized_url)
    gaps = []
    if features.get("IsHTTPS") == 0:
        gaps.append(TRAINING_DISTRIBUTION_GAPS["http_scheme"])
    if flags["is_apex"]:
        gaps.append(TRAINING_DISTRIBUTION_GAPS["apex_host"])
    elif flags["is_subdomain"]:
        gaps.append(TRAINING_DISTRIBUTION_GAPS["subdomain_host"])
    if flags["has_query"]:
        gaps.append(TRAINING_DISTRIBUTION_GAPS["query_string"])
    # normalize_url turns an empty path into "/", so length > 1 means a real path.
    if int(features.get("path_length") or 0) > 1:
        gaps.append(TRAINING_DISTRIBUTION_GAPS["path_component"])
    if flags["path_length"] >= 40:
        gaps.append(TRAINING_DISTRIBUTION_GAPS["long_path"])
    return gaps


def risk_level(label: int, confidence: float) -> str:
    """Map the shipped model's label and score onto a coarse risk band.

    Bands are presentation only. They are thresholds on the classifier's score,
    not calibrated probabilities.
    """
    if label == 0:
        if confidence >= 0.90:
            return "high"
        if confidence >= 0.70:
            return "elevated"
        return "moderate"
    if confidence >= 0.90:
        return "low"
    if confidence >= 0.70:
        return "low-to-moderate"
    return "uncertain"


def build_explanation(label: int, confidence: float, signals: list, gaps: list) -> list:
    """Assemble the explanation sentences. Never asserts anything about the site."""
    lines = []
    verdict = PREDICTION_PHISHING if label == 0 else PREDICTION_LEGITIMATE
    if label == 0:
        lines.append(
            f"The model classified this URL as {verdict} with a classifier score of "
            f"{round(confidence * 100, 1)}%, based only on URL-level characteristics.")
        lines.append(
            "This means the URL resembles the phishing examples in the training corpus. "
            "It is not evidence that the site itself is malicious.")
    else:
        lines.append(
            f"The model classified this URL as {verdict} with a classifier score of "
            f"{round(confidence * 100, 1)}%, based only on URL-level characteristics.")
        lines.append(
            "No phishing indicators were detected strongly enough by the model. "
            "This is not a confirmation that the site is safe.")

    risk_signals = [s for s in signals if s["risk_relevant"]]
    if label == 0 and risk_signals:
        highlights = "; ".join(s["observation"] for s in risk_signals[:4])
        lines.append(f"URL characteristics associated with phishing URLs: {highlights}.")
    elif label == 0:
        lines.append(
            "None of the individually suspicious URL tokens tracked by the model were present. "
            "The phishing classification is driven by the overall shape of the URL, which the "
            "model associates more closely with its phishing training examples than with its "
            "legitimate ones.")
    elif not risk_signals:
        lines.append("None of the phishing-associated URL characteristics tracked by the model were present.")

    if gaps:
        lines.append(
            "Caution: this URL's shape is underrepresented or absent among legitimate "
            "URLs in the training data, so the model's verdict is less reliable for it: "
            + "; ".join(gaps) + ".")
    return lines


def build_recommendation(label: int, gaps: list) -> tuple:
    """Return (primary recommendation, additional advisories)."""
    advisories = [
        "PhishGuard never opens the link. If you need to judge the site, open it in a "
        "separate browser profile or on a device you can reset.",
        "Check the registrable domain yourself rather than trusting brand-looking text "
        "in the subdomain.",
    ]
    if label == 0:
        primary = ("Do not enter passwords, card details, codes or other personal "
                   "information on this URL until you have independently verified the "
                   "site through a channel you already trust.")
        advisories.insert(0,
                          "If this link arrived by email, message or QR code, treat the "
                          "message itself as suspicious and verify with the supposed "
                          "sender using contact details you already had.")
    else:
        primary = ("Still confirm the destination before submitting anything sensitive. "
                   "A 'Legitimate' classification reflects URL shape only and does not "
                   "check who operates the site or what it serves.")
    if gaps:
        advisories.append(
            "This URL's structure is not well represented in the model's training data, "
            "so treat the verdict with extra caution and prefer manual verification.")
    return primary, advisories
