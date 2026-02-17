"""Pre-filter — fast domain rejection before running expensive deep analysis.

This eliminates clearly unsuitable domains instantly based on:
  - Domain name contains negative keywords
  - TLD not in preferred list
  - Domain name too long / contains numbers mixed weirdly
  - Age/DP/BL out of profile range
  - Known spam patterns in domain name
"""

from __future__ import annotations

import logging
import re

import tldextract

from domain_hunter.models import DomainCandidate
from domain_hunter.profiles import NicheProfile

logger = logging.getLogger(__name__)


def pre_filter(
    candidates: list[DomainCandidate],
    profile: NicheProfile,
) -> tuple[list[DomainCandidate], list[tuple[DomainCandidate, str]]]:
    """Fast-reject bad candidates and return (accepted, rejected_with_reason).

    This is designed to run before the expensive async analysis pipeline.
    """
    accepted: list[DomainCandidate] = []
    rejected: list[tuple[DomainCandidate, str]] = []

    for c in candidates:
        reason = _check_reject(c, profile)
        if reason:
            rejected.append((c, reason))
        else:
            accepted.append(c)

    logger.info(
        "Pre-filter: %d accepted, %d rejected (of %d total)",
        len(accepted), len(rejected), len(candidates),
    )

    return accepted, rejected


def _check_reject(c: DomainCandidate, p: NicheProfile) -> str | None:
    """Return a rejection reason string, or None if the candidate passes."""
    ext = tldextract.extract(c.domain)
    name = ext.domain.lower()
    tld = ext.suffix.lower()

    # ── 1. Negative keywords in domain name ──
    for kw in p.domain_negative_keywords:
        if kw in name:
            return f"域名含黑名單關鍵詞: {kw}"

    # ── 2. TLD check ─────────────────────────
    if p.preferred_tlds and tld not in p.preferred_tlds:
        return f"TLD .{tld} 不在偏好清單中"

    # ── 3. Domain name length ────────────────
    if len(name) > p.max_domain_length:
        return f"域名過長 ({len(name)} > {p.max_domain_length})"

    # ── 4. ASCII only check ──────────────────
    if p.require_english_chars and not name.isascii():
        return "域名包含非 ASCII 字元"

    # ── 5. Numeric spam pattern ──────────────
    # e.g., domain123456.com, x7k9m2.com
    if len(name) > 6:
        digit_ratio = sum(c.isdigit() for c in name) / len(name)
        if digit_ratio > 0.4:
            return f"域名數字比例過高 ({digit_ratio:.0%})"

    # ── 6. Domain age ────────────────────────
    if c.age and c.age < p.min_age:
        return f"域名年齡不足 ({c.age}y < {p.min_age}y)"

    if c.age and c.age > p.max_age:
        return f"域名年齡過大 ({c.age}y > {p.max_age}y)"

    # ── 7. Archive birth year ────────────────
    if c.aby and p.aby_before and c.aby > p.aby_before:
        return f"Archive 出生年份過晚 ({c.aby} > {p.aby_before})"

    # ── 8. Domain Pop (referring domains) ────
    if c.dp and c.dp > p.max_dp:
        return f"引用域名數過多 ({c.dp} > {p.max_dp})"

    # ── 9. Backlink count ────────────────────
    if c.bl and c.bl > p.max_bl:
        return f"反連數過多 ({c.bl} > {p.max_bl})"

    # ── 10. Known spam domain patterns ───────
    spam_patterns = [
        r"\d{4,}",          # 4+ consecutive digits
        r"(.)\1{3,}",       # 4+ repeated chars (aaaa, xxxxx)
        r"(buy|sell|cheap|free|best|top)\d+",  # spammy + numbers
    ]
    for pat in spam_patterns:
        if re.search(pat, name):
            return f"域名匹配垃圾模式: {pat}"

    # ── 11. Hyphen abuse ─────────────────────
    if name.count("-") >= 3:
        return f"域名連字號過多 ({name.count('-')})"

    # ── 12. Positive keyword boost check ─────
    # Not a rejection — just logging
    has_positive = any(kw in name for kw in p.domain_positive_keywords)
    if has_positive:
        logger.debug("  ✓ %s matches positive keywords", c.domain)

    return None  # passed all checks
