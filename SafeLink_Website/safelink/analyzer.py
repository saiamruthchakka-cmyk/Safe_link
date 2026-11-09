"""Explainable, local-only URL and email risk analysis. Does not visit URLs."""
import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
PRESSURE_WORDS = {
    "urgent": 8, "immediately": 8, "suspended": 10, "suspend": 8,
    "verify": 6, "verification": 6, "password": 8, "otp": 10,
    "one-time password": 10, "account locked": 10, "limited time": 6,
    "prize": 6, "winner": 6, "refund": 5, "payment failed": 7,
    "click here": 6, "confirm your account": 10, "bank account": 4,
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at", "rebrand.ly"
}
BRAND_WORDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co.in"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "sbi": ["sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
}

def _domain_matches(host, allowed):
    return any(host == d or host.endswith("." + d) for d in allowed)

def _risk_label(score):
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "SUSPICIOUS"
    return "LOW INDICATORS"

def analyze_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Paste a URL before scanning.")
    if any(ch.isspace() for ch in raw):
        raise ValueError("A URL should not contain spaces. Use the Email Scanner for message text.")
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid web address, such as https://example.com.")
    host = (parsed.hostname or "").lower().rstrip(".")
    findings = []

    def add(points, title, explanation):
        findings.append({"points": points, "title": title, "explanation": explanation})

    if parsed.scheme.lower() == "http":
        add(12, "Unencrypted connection", "The URL uses HTTP. Data sent through it may not be encrypted.")
    if "@" in parsed.netloc:
        add(22, "Potentially misleading address", "The @ symbol can make text before it look like the destination even when it is not.")
    try:
        ipaddress.ip_address(host.strip("[]"))
        add(22, "IP address used as host", "The link uses a raw IP address instead of a normal domain name. This can be legitimate, but deserves checking.")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        add(18, "Encoded domain name", "A punycode label can represent unusual characters that resemble another domain.")
    if host in SHORTENERS:
        add(18, "Shortened link", "The final destination is hidden behind a URL-shortening service.")
    if len(host) > 35:
        add(10, "Long hostname", "The hostname is unusually long and may be designed to obscure the real domain.")
    if host.count(".") >= 4:
        add(10, "Many subdomains", "Several subdomain levels can make the actual registered domain harder to notice.")
    if "-" in host:
        add(5, "Hyphen in hostname", "Hyphens are allowed in normal domains, but can also appear in impersonation domains.")
    if len(candidate) > 120:
        add(8, "Unusually long URL", "Long URLs can hide confusing paths or parameters.")
    if len(parsed.query) > 100:
        add(8, "Long query string", "The URL has a long parameter section. Inspect it carefully before opening.")
    if re.search(r'(%[0-9a-fA-F]{2}){3,}', candidate):
        add(8, "Encoded characters", "Several encoded characters may make the destination harder to read.")
    for brand, domains in BRAND_WORDS.items():
        if brand in host and not _domain_matches(host, domains):
            add(22, f"Possible {brand.title()} impersonation", f"The hostname contains '{brand}' but is not one of the common official domains configured in this demo.")
            break

    score = min(100, sum(x["points"] for x in findings))
    if not findings:
        findings.append({
            "points": 0, "title": "No configured warning signs found",
            "explanation": "This simple local check did not find its known warning patterns. It cannot prove the website is safe."
        })
    return {
        "kind": "URL", "input": raw, "normalized": candidate, "domain": host,
        "score": score, "label": _risk_label(score), "findings": findings,
        "advice": _advice(score), "method": "Local explainable rules"
    }

def analyze_email(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Paste an email message before scanning.")
    low = raw.lower()
    findings = []

    def add(points, title, explanation):
        findings.append({"points": points, "title": title, "explanation": explanation})

    for phrase, points in PRESSURE_WORDS.items():
        if phrase in low:
            add(points, f"Pressure phrase: “{phrase}”", "Scam messages often use urgency, fear, prizes or account threats to rush a decision.")
    urls = URL_RE.findall(raw)
    if urls:
        add(min(20, len(urls) * 7), "Link included in message", f"Found {len(urls)} web link(s). Inspect the real domain before opening any link.")
    if re.search(r'\b(password|otp|one-time password|pin|cvv)\b', low):
        add(12, "Requests sensitive information", "Treat requests for passwords, OTPs, PINs or CVVs as a serious warning sign.")
    if re.search(r'\b(send|pay|transfer)\b.{0,50}\b(money|cash|fee|gift card|crypto)\b', low):
        add(10, "Payment pressure", "Unexpected payment or transfer requests should be independently verified.")
    if re.search(r'\b(dear customer|dear user|valued customer)\b', low):
        add(4, "Generic greeting", "A generic greeting is not proof of fraud, but may be worth checking with other indicators.")
    score = min(100, sum(x["points"] for x in findings))
    if not findings:
        findings.append({
            "points": 0, "title": "No configured warning signs found",
            "explanation": "The message did not match this demo's known patterns. That does not prove it is genuine."
        })
    return {
        "kind": "EMAIL", "input": raw[:5000], "normalized": "",
        "domain": "", "score": score, "label": _risk_label(score),
        "findings": findings, "advice": _advice(score),
        "method": "Local explainable text rules"
    }

def _advice(score):
    if score >= 60:
        return "Do not open the link or provide information. Verify through the organisation's official app or a phone number you already trust."
    if score >= 30:
        return "Pause and verify the sender and destination independently. Do not share passwords, OTPs, PINs or payment details."
    return "No configured warning pattern was detected. This is not a safety guarantee. Check the domain and sender before sharing information."
