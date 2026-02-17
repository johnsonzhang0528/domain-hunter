"""Content classification — detect spam, adult, gambling, PBN patterns."""

from __future__ import annotations

import re

from domain_hunter import config as cfg

# Pre-compile patterns for speed
_GAMBLING_RE = re.compile(
    r"\b("
    r"casino|poker|bet(?:ting)?|gambl(?:e|ing)|slots?|blackjack|roulette|"
    r"sportsbook|baccarat|lottery|jackpot|wager|bookmaker|odds\s?maker"
    r")\b",
    re.I,
)

_ADULT_RE = re.compile(
    r"\b("
    r"porn(?:ography)?|xxx|adult\s?video|escort|nude|naked|"
    r"webcam\s?girl|onlyfans|hentai|erotic|sex\s?chat|"
    r"strip(?:tease)?|milf|nsfw"
    r")\b",
    re.I,
)

_PHARMA_RE = re.compile(
    r"\b("
    r"viagra|cialis|pharmacy|phentermine|xanax|tramadol|"
    r"hydrocodone|oxycodone|modafinil|buy\s?pills|cheap\s?meds|"
    r"online\s?pharmacy|prescription\s?free"
    r")\b",
    re.I,
)

_MALWARE_RE = re.compile(
    r"\b("
    r"crack|keygen|warez|nulled|activator|pirat(?:e|ed)|"
    r"free\s?download\s?full|serial\s?key|patch\s?crack"
    r")\b",
    re.I,
)

_PBN_PATTERNS = [
    re.compile(r"powered\s+by\s+wordpress", re.I),
    re.compile(r"theme\s+by\s+flavor|flavor\s*theme", re.I),
    re.compile(r"lorem\s+ipsum", re.I),
    re.compile(r"sample\s+page|hello\s+world", re.I),
    re.compile(r"just\s+another\s+wordpress\s+site", re.I),
    re.compile(r"this\s+domain\s+(may\s+be|is)\s+for\s+sale", re.I),
]

_LINK_FARM_RE = re.compile(
    r"\b("
    r"buy\s?backlinks?|link\s?building\s?service|"
    r"guest\s?post\s?service|seo\s?package|link\s?exchange"
    r")\b",
    re.I,
)

_REDIRECT_INDICATORS = [
    re.compile(r"<meta\s+http-equiv=['\"]refresh['\"]", re.I),
    re.compile(r"window\.location\s*=", re.I),
    re.compile(r"document\.location\s*=", re.I),
    re.compile(r"301\s+moved\s+permanently", re.I),
]

_PARKED_RE = re.compile(
    r"\b("
    r"domain\s+(is\s+)?for\s+sale|buy\s+this\s+domain|"
    r"parked\s+(free|domain)|this\s+page\s+is\s+parked|"
    r"make\s+an?\s+offer|domain\s+parking|"
    r"sedoparking|bodis|hugedomains|afternic|dan\.com"
    r")\b",
    re.I,
)

_CONTENT_FARM_RE = re.compile(
    r"\b("
    r"click\s+here\s+to\s+read\s+more|"
    r"you\s+may\s+also\s+like|related\s+articles?\s*:|"
    r"trending\s+now|sponsored\s+content|"
    r"advertisement|adsbygoogle"
    r")\b",
    re.I,
)


def classify_content(
    title: str,
    meta_description: str,
    body_text: str,
) -> list[str]:
    """Classify combined text and return detected category labels.

    Returns a list of zero or more categories:
      gambling, adult, pharma, malware, pbn_spam, link_farm,
      redirect_page, parked, content_farm, niche_match
    """
    combined = f"{title} {meta_description} {body_text}"
    categories: list[str] = []

    # ── Negative categories ──────────────────
    if _count_matches(_GAMBLING_RE, combined) >= 2:
        categories.append("gambling")

    if _count_matches(_ADULT_RE, combined) >= 2:
        categories.append("adult")

    if _count_matches(_PHARMA_RE, combined) >= 2:
        categories.append("pharma")

    if _count_matches(_MALWARE_RE, combined) >= 1:
        categories.append("malware")

    if any(p.search(combined) for p in _PBN_PATTERNS):
        # Additional check: very short body means PBN
        if len(body_text.strip()) < 300:
            categories.append("pbn_spam")

    if _LINK_FARM_RE.search(combined):
        categories.append("link_farm")

    if any(p.search(combined) for p in _REDIRECT_INDICATORS):
        categories.append("redirect_page")

    if _PARKED_RE.search(combined):
        categories.append("parked")

    # Content farm: excessive ads-related markers
    if _count_matches(_CONTENT_FARM_RE, combined) >= 3:
        categories.append("content_farm")

    # ── Positive: niche relevance ────────────
    niche_hits = sum(
        1 for kw in cfg.NICHE_KEYWORDS
        if re.search(rf"\b{re.escape(kw)}\b", combined, re.I)
    )
    if niche_hits >= 3:
        categories.append("niche_match")

    return categories


def classify_anchor_text(anchor: str) -> str | None:
    """Return a spam category if anchor text is suspicious, else None."""
    a = anchor.lower()
    if _GAMBLING_RE.search(a):
        return "gambling"
    if _ADULT_RE.search(a):
        return "adult"
    if _PHARMA_RE.search(a):
        return "pharma"
    if _MALWARE_RE.search(a):
        return "malware"
    return None


def is_spam_domain(domain: str) -> tuple[bool, str]:
    """Quick check if a referring domain looks spammy.

    Returns (is_spam, reason).
    """
    import tldextract

    ext = tldextract.extract(domain)

    # Spam TLD check
    if ext.suffix.lower() in cfg.SPAM_TLDS:
        return True, f"spam TLD (.{ext.suffix})"

    # Keyword in domain name
    name = ext.domain.lower()
    for kw in ("casino", "poker", "slot", "porn", "xxx", "adult", "viagra", "pharma"):
        if kw in name:
            return True, f"spam keyword in domain ({kw})"

    # Excessively long random domain (typical PBN)
    if len(name) > 25 and sum(c.isdigit() for c in name) > 5:
        return True, "suspicious random domain name"

    return False, ""


def _count_matches(pattern: re.Pattern, text: str) -> int:
    return len(pattern.findall(text))
