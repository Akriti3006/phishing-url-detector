import json
import math
import os
import re
from urllib.parse import urlparse
from collections import Counter

SUSPICIOUS_WORDS = {
    "login", "signin", "bank", "account", "update", "verify", "secure",
    "ebayisapi", "webscr", "confirm", "password", "security", "wallet"
}
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
SCRIPT_EXTS = {".js", ".php", ".asp", ".aspx", ".cgi", ".sh", ".py"}

SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)

# The original 25 features. These are the ONLY ones saved to the url_features
# table, so the database schema does not need to change.
DB_FEATURES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots",
    "num_subdomains", "num_hyphens", "host_hyphens", "num_slashes", "path_depth",
    "num_special_chars", "num_digits", "digit_ratio", "host_digits", "num_params",
    "num_percent", "has_at", "has_ip", "has_https", "has_port",
    "num_suspicious_words", "suspicious_tld", "is_shortener", "has_script_ext",
    "url_entropy",
]

# ---- Domain "naturalness" model (character bigrams learned from popular domains) ----
BIGRAM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bigrams.json")
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "ne", "or"}
VOWELS = set("aeiou")
_BIGRAMS = None


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def canonicalize(url):
    """Strip scheme and leading www., lowercase, drop a bare trailing slash.
    Used for BOTH training and inference so the model never sees formatting quirks."""
    s = SCHEME_RE.sub("", str(url).strip()).lower()
    if s.startswith("www."):
        s = s[4:]
    if s.endswith("/") and s.find("/") == len(s) - 1:
        s = s[:-1]
    return s


def host_of(url):
    c = canonicalize(url)
    return re.split(r"[/?#:]", c, maxsplit=1)[0]


def sld_of_host(host):
    """Main label of a domain: mail.google.com -> google, shop.example.co.uk -> example."""
    labels = [l for l in host.split(".") if l]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def _clean(s):
    return "".join(ch for ch in s if ch in ALPHABET)


def build_bigram_table(domains):
    counts, first = Counter(), Counter()
    for d in domains:
        s = _clean(sld_of_host(str(d).strip().lower()))
        if len(s) < 2:
            continue
        p = "^" + s + "$"
        for a, b in zip(p, p[1:]):
            counts[(a, b)] += 1
            first[a] += 1
    V = len(ALPHABET) + 1
    table = {}
    for a in "^" + ALPHABET:
        for b in ALPHABET + "$":
            table[a + b] = math.log((counts[(a, b)] + 1) / (first[a] + V))
    return {"logp": table, "default": min(table.values())}


def save_bigram_table(domains, path=BIGRAM_PATH):
    global _BIGRAMS
    table = build_bigram_table(domains)
    with open(path, "w") as f:
        json.dump(table, f)
    _BIGRAMS = table


def _get_bigrams():
    global _BIGRAMS
    if _BIGRAMS is None:
        try:
            with open(BIGRAM_PATH) as f:
                _BIGRAMS = json.load(f)
        except Exception:
            _BIGRAMS = {}
    return _BIGRAMS


def naturalness(sld):
    """Average log-probability of the domain name's letter pairs.
    Real names score higher (closer to 0); random strings score lower (more negative).
    Returns 0.0 when no bigram table is available."""
    table = _get_bigrams()
    s = _clean(sld)
    if not table or len(s) < 2:
        return 0.0
    p = "^" + s + "$"
    logp, default = table["logp"], table["default"]
    scores = [logp.get(a + b, default) for a, b in zip(p, p[1:])]
    return round(sum(scores) / len(scores), 4)


def max_consonant_run(s):
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def extract_features(url):
    original = str(url).strip()
    raw_url = canonicalize(original)

    try:
        parsed = urlparse("http://" + raw_url)
        netloc = parsed.netloc or ""
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        host, path, query, netloc = raw_url, "", "", ""

    digits = sum(c.isdigit() for c in raw_url)
    host_digits = sum(c.isdigit() for c in host)
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0

    # Domain-name features (skipped for raw IP addresses)
    sld = "" if has_ip else sld_of_host(host)
    letters = [c for c in sld if c.isalpha()]

    return {
        "url_length": len(raw_url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw_url.count("."),
        "num_subdomains": max(host.count(".") - 1, 0),
        "num_hyphens": raw_url.count("-"),
        "host_hyphens": host.count("-"),
        "num_slashes": raw_url.count("/"),
        "path_depth": len([seg for seg in path.split("/") if seg]),
        "num_special_chars": len(re.findall(r"[-_.~!*'();:@&=+$,/?%#\[\]]", raw_url)),
        "num_digits": digits,
        "digit_ratio": round(digits / len(raw_url), 4) if raw_url else 0.0,
        "host_digits": host_digits,
        "num_params": len(query.split("&")) if query else 0,
        "num_percent": raw_url.count("%"),
        "has_at": 1 if "@" in raw_url else 0,
        "has_ip": has_ip,
        # Kept only so the DB insert in app.py still matches the url_features table.
        # It is NOT used by the model (dropped in train.py).
        "has_https": 1 if original.lower().startswith("https://") else 0,
        "has_port": 1 if ":" in netloc else 0,
        "num_suspicious_words": sum(1 for w in SUSPICIOUS_WORDS if w in raw_url),
        "suspicious_tld": 1 if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0,
        "is_shortener": 1 if host in SHORTENERS else 0,
        "has_script_ext": 1 if any(path.endswith(ext) for ext in SCRIPT_EXTS) else 0,
        "url_entropy": round(entropy(raw_url), 4),
        # ---- New: domain-name randomness features (model only, not saved to DB) ----
        "host_entropy": round(entropy(host), 4),
        "sld_length": len(sld),
        "sld_entropy": round(entropy(sld), 4),
        "sld_vowel_ratio": round(sum(c in VOWELS for c in letters) / len(letters), 4) if letters else 0.0,
        "sld_max_consonant_run": max_consonant_run(sld),
        "sld_digit_ratio": round(sum(c.isdigit() for c in sld) / len(sld), 4) if sld else 0.0,
        "sld_naturalness": naturalness(sld),
    }