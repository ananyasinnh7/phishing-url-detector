"""URL feature extraction with no network access."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

FEATURE_NAMES = ["url_length", "hostname_length", "path_length", "query_length", "dot_count", "subdomain_count", "path_segment_count", "has_ip", "uses_https", "suspicious_keyword_count", "special_char_count", "percent_encoded_count", "has_at_symbol", "has_port", "is_shortener"]
SUSPICIOUS_WORDS = {"login", "signin", "verify", "verification", "secure", "account", "update", "password", "confirm", "wallet", "bank", "gift", "prize", "free", "claim", "suspend", "urgent", "reset"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL is required")
    candidate = value if re.match(r"^https?://", value, re.I) else f"https://{value}"
    if any(char.isspace() for char in candidate):
        raise ValueError("URL must not contain spaces")
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL")
    return candidate


def _has_ip(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_features(url: str) -> dict[str, float]:
    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    hostname = (parts.hostname or "").lower()
    tokens = set(re.findall(r"[a-z0-9]+", normalized.lower()))
    keyword_count = sum(word in tokens for word in SUSPICIOUS_WORDS)
    labels = [part for part in hostname.split(".") if part]
    return {
        "url_length": float(len(normalized)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(parts.path)),
        "query_length": float(len(parts.query)),
        "dot_count": float(normalized.count(".")),
        "subdomain_count": float(max(0, len(labels) - 2)),
        "path_segment_count": float(len([x for x in parts.path.split("/") if x])),
        "has_ip": float(_has_ip(hostname)),
        "uses_https": float(parts.scheme.lower() == "https"),
        "suspicious_keyword_count": float(keyword_count),
        "special_char_count": float(sum(normalized.count(c) for c in ["@", "-", "_", "="])),
        "percent_encoded_count": float(normalized.count("%")),
        "has_at_symbol": float("@" in normalized),
        "has_port": float(parts.port is not None),
        "is_shortener": float(hostname in SHORTENERS),
    }
