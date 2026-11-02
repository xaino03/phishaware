"""Explainable, offline phishing triage helpers used by the Flask app."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

MAX_INPUT = 20_000
URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"']{3,2048}")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "country", "stream", "gq", "tk", "ml", "cf"}
BRANDS = {"paypal", "microsoft", "office", "google", "apple", "amazon", "netflix", "facebook", "instagram", "bank", "docusign", "dropbox", "adobe"}
SUSPICIOUS_WORDS = {"login", "verify", "secure", "account", "password", "update", "wallet", "invoice", "payment", "signin", "auth", "confirm", "suspended", "recover"}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def analyze_url(raw: str) -> dict:
    raw = raw.strip().rstrip(".,);]}")
    candidate = raw if re.match(r"(?i)^https?://", raw) else "https://" + raw
    findings: list[dict] = []
    score = 0

    def add(points: int, title: str, detail: str) -> None:
        nonlocal score
        score += points
        findings.append({"points": points, "title": title, "detail": detail})

    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host or "." not in host:
            raise ValueError("Missing hostname")
        try:
            ipaddress.ip_address(host)
            add(25, "IP address used as host", "The link points directly to an IP address instead of a recognizable domain.")
        except ValueError:
            pass
        try:
            decoded_host = host.encode("ascii").decode("idna")
            if decoded_host != host:
                add(25, "Internationalized domain", f"The hostname decodes to “{decoded_host}”. Check for lookalike characters.")
        except (UnicodeError, ValueError):
            pass
        if parsed.username is not None or parsed.password is not None:
            add(30, "Credentials embedded in URL", "Text before @ can disguise the actual destination hostname.")
        if host in SHORTENERS:
            add(18, "Link shortener", "The final destination is hidden until the short link is resolved.")
        tld = host.split(".")[-1]
        if tld in RISKY_TLDS:
            add(12, "Higher-risk top-level domain", f"The domain ends in .{tld}; this alone does not prove abuse.")
        if len(host) > 50:
            add(10, "Unusually long hostname", f"Hostname is {len(host)} characters long.")
        if host.count("-") >= 3:
            add(8, "Many hyphens in hostname", "Multiple hyphens can make a lookalike domain harder to read.")
        if sum(character.isdigit() for character in host) >= 5:
            add(8, "Many digits in hostname", "The hostname contains an unusual number of digits.")
        brand_hits = sorted(brand for brand in BRANDS if re.search(r"(?:^|[^a-z0-9])" + re.escape(brand) + r"(?:[^a-z0-9]|$)", host))
        if brand_hits and not any(host == brand + ".com" or host.endswith("." + brand + ".com") for brand in brand_hits):
            add(16, "Brand name in non-brand hostname", "Contains " + ", ".join(brand_hits) + " but is not its usual .com domain; check the registered domain carefully.")
        path_query = unquote((parsed.path or "") + "?" + (parsed.query or "")).lower()
        word_hits = sorted(word for word in SUSPICIOUS_WORDS if re.search(r"(?:^|[^a-z])" + re.escape(word) + r"(?:$|[^a-z])", path_query))
        if word_hits:
            add(min(15, 5 + len(word_hits) * 2), "Credential or urgency language", "URL path/query includes: " + ", ".join(word_hits) + ".")
        if parsed.scheme.lower() != "https":
            add(10, "No HTTPS", "The link uses plain HTTP. HTTPS does not itself make a site trustworthy.")
        if len(parsed.query) > 180:
            add(6, "Long query string", f"The query string is {len(parsed.query)} characters long and may contain tracking or encoded data.")
        if _entropy(host) > 3.8 and len(host) > 18:
            add(8, "High-entropy hostname", "The hostname has a random-looking character mix.")
        if not findings:
            findings.append({"points": 0, "title": "No strong static indicators", "detail": "This URL passed the checks in this tool. That does not establish that it is safe."})
        score = min(100, score)
        level = "High risk" if score >= 50 else "Needs review" if score >= 25 else "Lower signal"
        return {"url": raw, "host": host, "score": score, "level": level, "findings": findings}
    except Exception:
        return {"url": raw, "host": "", "score": 0, "level": "Could not parse", "findings": [{"points": 0, "title": "Invalid or incomplete URL", "detail": "Provide a URL with a hostname, such as https://example.com/path."}]}


def analyze_text(text: str) -> dict:
    urls = list(dict.fromkeys(match.rstrip(".,);]}") for match in URL_RE.findall(text)))
    results = [analyze_url(url) for url in urls[:30]]
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))
    lowered = text.lower()
    urgency = [phrase for phrase in ("urgent", "immediately", "within 24 hours", "suspended", "act now", "final notice", "unusual activity") if phrase in lowered]
    flags = []
    if urgency:
        flags.append({"title": "Urgency or threat language", "detail": "Message includes: " + ", ".join(urgency) + ". This can pressure recipients into acting quickly."})
    if re.search(r"(?i)\b(password|one[- ]time code|verification code|social security|bank details)\b", text):
        flags.append({"title": "Sensitive information mentioned", "detail": "Check whether the message asks for credentials, codes, or financial information."})
    return {"urls": results, "emails": emails[:30], "message_flags": flags, "score": max((item["score"] for item in results), default=0)}
