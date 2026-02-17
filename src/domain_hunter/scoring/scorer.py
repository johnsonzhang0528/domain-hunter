"""Composite scoring engine — combines all analyzer scores into a final verdict."""

from __future__ import annotations

from domain_hunter import config as cfg
from domain_hunter.models import DomainReport, Verdict


def compute_final_score(report: DomainReport) -> DomainReport:
    """Compute the final weighted score and set verdict + reasons.

    Mutates and returns the same *report* object.
    """
    weights = cfg.SCORE_WEIGHTS
    rejection_reasons: list[str] = []
    positive_signals: list[str] = []

    # ── Component scores ─────────────────────
    wayback_score = report.wayback.score
    backlink_score = report.backlinks.score
    safety_score = report.safety.score
    dns_score = report.dns.score

    # ── Niche relevance score ────────────────
    niche_score = _compute_niche_score(report)

    # ── Domain age score ─────────────────────
    age_score = _compute_age_score(report)

    # ── Weighted total ───────────────────────
    total = (
        wayback_score * weights["wayback"]
        + backlink_score * weights["backlinks"]
        + safety_score * weights["safety"]
        + niche_score * weights["niche_relevance"]
        + age_score * weights["domain_age"]
        + dns_score * weights["dns_availability"]
    ) / sum(weights.values())

    report.total_score = round(total, 1)

    # ── Collect rejection reasons ────────────
    # Hard rejections (regardless of score)
    if report.wayback.spam_flags:
        for flag in report.wayback.spam_flags:
            rejection_reasons.append(f"歷史內容含 {flag} 類別")

    if report.backlinks.spam_ratio > 0.3:
        rejection_reasons.append(
            f"垃圾反向連結比例過高 ({report.backlinks.spam_ratio:.0%})"
        )

    if not report.safety.is_safe:
        for src in report.safety.blacklisted_on:
            rejection_reasons.append(f"被 {src} 黑名單標記")

    if report.backlinks.spam_anchors:
        n = len(report.backlinks.spam_anchors)
        rejection_reasons.append(f"發現 {n} 個垃圾錨文本")

    # Soft warnings
    if wayback_score < 40:
        rejection_reasons.append("Wayback 歷史評分過低")

    if backlink_score < 40:
        rejection_reasons.append("反向連結品質評分過低")

    # ── Collect positive signals ─────────────
    if "niche_match" in report.wayback.detected_categories:
        positive_signals.append("歷史內容與目標利基相關")

    if report.wayback.total_snapshots > 50:
        positive_signals.append(f"豐富的存檔歷史 ({report.wayback.total_snapshots} 快照)")

    if len(report.wayback.snapshot_years) >= 5:
        positive_signals.append(f"域名活躍 {len(report.wayback.snapshot_years)} 年")

    if report.backlinks.spam_ratio < 0.05 and report.backlinks.referring_domains > 0:
        positive_signals.append("反向連結乾淨")

    if report.whois.age_years >= 5:
        positive_signals.append(f"域名年齡 {report.whois.age_years} 年")

    if report.safety.is_safe:
        positive_signals.append("安全檢查通過")

    if not report.dns.is_registered:
        positive_signals.append("域名可註冊")

    if report.backlinks.page_rank > 3:
        positive_signals.append(f"PageRank {report.backlinks.page_rank:.1f}")

    # ── Determine verdict ────────────────────
    # Hard reject if any critical flags
    hard_reject = bool(report.wayback.spam_flags) or not report.safety.is_safe
    if report.backlinks.spam_ratio > 0.5:
        hard_reject = True

    if hard_reject:
        verdict = Verdict.REJECT
    elif total >= cfg.VERDICT_THRESHOLDS["buy"]:
        verdict = Verdict.BUY
    elif total >= cfg.VERDICT_THRESHOLDS["maybe"]:
        verdict = Verdict.MAYBE
    else:
        verdict = Verdict.REJECT

    report.verdict = verdict
    report.rejection_reasons = rejection_reasons
    report.positive_signals = positive_signals

    return report


def _compute_niche_score(report: DomainReport) -> float:
    """Score 0–100 based on content relevance to target niche."""
    categories = set(report.wayback.detected_categories)

    if "niche_match" in categories:
        return 100.0

    # Check domain name for niche keywords
    domain_lower = report.domain.lower()
    import re
    hits = sum(
        1
        for kw in cfg.NICHE_KEYWORDS
        if re.search(rf"{re.escape(kw)}", domain_lower)
    )

    if hits >= 2:
        return 80.0
    if hits == 1:
        return 60.0

    return 40.0  # neutral — no niche signal either way


def _compute_age_score(report: DomainReport) -> float:
    """Score 0–100 based on domain age."""
    age = report.whois.age_years or report.candidate.age

    if not age and report.candidate.aby:
        from datetime import datetime
        age = datetime.now().year - report.candidate.aby

    if not age and report.wayback.snapshot_years:
        from datetime import datetime
        age = datetime.now().year - min(report.wayback.snapshot_years)

    if age is None or age <= 0:
        return 30.0

    if age >= 15:
        return 100.0
    if age >= 10:
        return 85.0
    if age >= 5:
        return 70.0
    if age >= 3:
        return 55.0
    if age >= 1:
        return 40.0

    return 30.0
