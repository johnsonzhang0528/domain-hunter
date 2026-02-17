"""Wayback Machine CDX API integration + snapshot content analysis."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from domain_hunter import config as cfg
from domain_hunter.models import WaybackResult, WaybackSnapshot
from domain_hunter.analyzers.content_classifier import classify_content

logger = logging.getLogger(__name__)


async def analyze(
    domain: str,
    session: aiohttp.ClientSession,
    max_snapshots: int | None = None,
) -> WaybackResult:
    """Run full Wayback Machine analysis for *domain*.

    1.  Query CDX API for snapshot index
    2.  Pick representative snapshots (spread across years)
    3.  Fetch each snapshot, extract text, classify content
    4.  Aggregate and score
    """
    max_snapshots = max_snapshots or cfg.WAYBACK_MAX_SNAPSHOTS
    result = WaybackResult()

    try:
        # ── Step 1: CDX index query ──────────────
        cdx_rows = await _fetch_cdx_index(domain, session)
        if not cdx_rows:
            result.error = "No snapshots found in Wayback Machine"
            result.score = 50.0  # neutral — no history
            return result

        result.total_snapshots = len(cdx_rows)
        result.first_seen = cdx_rows[0][0][:8]  # YYYYMMDD
        result.last_seen = cdx_rows[-1][0][:8]

        # Extract unique years
        years = sorted({int(r[0][:4]) for r in cdx_rows})
        result.snapshot_years = years

        # ── Step 2: pick representative snapshots ─
        selected = _select_representative(cdx_rows, max_snapshots)

        # ── Step 3: fetch & classify ─────────────
        tasks = [
            _fetch_and_classify(ts, url, domain, session)
            for ts, url in selected
        ]
        snapshots = await asyncio.gather(*tasks, return_exceptions=True)

        for snap in snapshots:
            if isinstance(snap, Exception):
                logger.warning("Snapshot fetch error: %s", snap)
                continue
            if snap is None:
                continue
            result.snapshots_analyzed.append(snap)
            result.sample_titles.append(snap.title)
            result.detected_categories.extend(snap.detected_categories)
            if snap.language and snap.language not in result.languages_detected:
                result.languages_detected.append(snap.language)

        # ── Step 4: aggregate spam flags ─────────
        category_set = set(result.detected_categories)
        spam_cats = category_set & {"gambling", "adult", "pharma", "malware", "pbn_spam"}
        result.spam_flags = sorted(spam_cats)

        # Deduplicate
        result.detected_categories = sorted(set(result.detected_categories))
        result.sample_titles = [t for t in dict.fromkeys(result.sample_titles) if t]

        # ── Step 5: score ────────────────────────
        result.score = _compute_score(result)

    except Exception as exc:
        logger.exception("Wayback analysis error for %s", domain)
        result.error = str(exc)
        result.score = 0.0

    return result


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

async def _fetch_cdx_index(
    domain: str,
    session: aiohttp.ClientSession,
) -> list[list[str]]:
    """Query CDX API and return list of [timestamp, original_url, statuscode, mimetype]."""
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": "mimetype:text/html",
        "collapse": "timestamp:6",  # collapse to monthly
        "limit": "500",
    }
    try:
        async with session.get(
            cfg.WAYBACK_CDX_URL,
            params=params,
            timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
            if not data or len(data) < 2:
                return []
            return data[1:]  # skip header row
    except Exception as exc:
        logger.warning("CDX fetch failed for %s: %s", domain, exc)
        return []


def _select_representative(
    rows: list[list[str]],
    n: int,
) -> list[tuple[str, str]]:
    """Pick *n* snapshots spread across the timeline."""
    if len(rows) <= n:
        return [(r[0], r[1]) for r in rows]

    # Group by year, pick one from each year first
    by_year: dict[int, list] = {}
    for r in rows:
        yr = int(r[0][:4])
        by_year.setdefault(yr, []).append(r)

    selected: list[tuple[str, str]] = []
    for yr in sorted(by_year):
        mid = len(by_year[yr]) // 2
        row = by_year[yr][mid]
        selected.append((row[0], row[1]))
        if len(selected) >= n:
            break

    # If still under budget, fill with evenly-spaced picks
    if len(selected) < n:
        step = max(1, len(rows) // (n - len(selected)))
        existing_ts = {s[0] for s in selected}
        for i in range(0, len(rows), step):
            if rows[i][0] not in existing_ts:
                selected.append((rows[i][0], rows[i][1]))
                if len(selected) >= n:
                    break

    return selected[:n]


async def _fetch_and_classify(
    timestamp: str,
    original_url: str,
    domain: str,
    session: aiohttp.ClientSession,
) -> WaybackSnapshot | None:
    """Fetch one Wayback snapshot and classify its content."""
    fetch_url = cfg.WAYBACK_FETCH_URL.format(ts=timestamp, url=original_url)

    try:
        async with session.get(
            fetch_url,
            timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                return None
            html = await resp.text(errors="replace")
    except Exception as exc:
        logger.debug("Failed to fetch snapshot %s: %s", timestamp, exc)
        return None

    soup = BeautifulSoup(html, "lxml")

    # Remove Wayback toolbar
    for wb in soup.select("#wm-ipp-base, #wm-ipp, #donato, #wm-ipp-print"):
        wb.decompose()

    title = (soup.title.string or "").strip() if soup.title else ""
    meta_desc = ""
    meta_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
    if meta_tag and meta_tag.get("content"):
        meta_desc = meta_tag["content"].strip()

    # Body text (limit to avoid huge strings)
    body_text = soup.get_text(separator=" ", strip=True)[:5000]

    # Detect language (simple heuristic)
    lang = ""
    html_tag = soup.find("html")
    if html_tag:
        lang = html_tag.get("lang", "") or html_tag.get("xml:lang", "")
    if not lang:
        lang = _guess_language(body_text[:500])

    # Classify
    categories = classify_content(title, meta_desc, body_text)

    return WaybackSnapshot(
        timestamp=timestamp,
        url=original_url,
        title=title,
        meta_description=meta_desc,
        body_text_preview=body_text[:300],
        language=lang.lower()[:5],
        detected_categories=categories,
    )


def _guess_language(text: str) -> str:
    """Very simple language detection heuristic."""
    cjk = sum(1 for c in text if "\u4e00" <= c <= "\u9fff")
    jp = sum(1 for c in text if "\u3040" <= c <= "\u30ff")
    kr = sum(1 for c in text if "\uac00" <= c <= "\ud7af")

    total = len(text) or 1
    if cjk / total > 0.1 and jp / total < 0.03:
        return "zh"
    if jp / total > 0.05:
        return "ja"
    if kr / total > 0.05:
        return "ko"
    return "en"


def _compute_score(result: WaybackResult) -> float:
    """Score 0–100 based on Wayback analysis.

    Deductions:
      - spam categories found          → heavy penalty
      - very few snapshots              → slight penalty
      - suspected content farm / PBN    → medium penalty
      - no history at all               → neutral (50)
    """
    score = 100.0

    # Spam category penalties
    penalty_map = {
        "gambling": 40,
        "adult": 40,
        "pharma": 35,
        "malware": 40,
        "pbn_spam": 30,
        "link_farm": 25,
        "redirect_page": 15,
        "parked": 10,
        "content_farm": 20,
    }
    for cat in set(result.detected_categories):
        score -= penalty_map.get(cat, 5)

    # Very few snapshots might mean domain was barely used (slight penalty)
    if result.total_snapshots < 5:
        score -= 5

    # Bonus for long clean history
    if len(result.snapshot_years) >= 5 and not result.spam_flags:
        score += 5

    return max(0.0, min(100.0, score))
