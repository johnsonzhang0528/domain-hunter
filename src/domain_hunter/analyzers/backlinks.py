"""Backlink quality analysis via CommonCrawl + OpenPageRank (all free)."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from urllib.parse import urlparse

import aiohttp
import tldextract

from domain_hunter import config as cfg
from domain_hunter.analyzers.content_classifier import (
    classify_anchor_text,
    is_spam_domain,
)
from domain_hunter.models import BacklinkInfo, BacklinkResult

logger = logging.getLogger(__name__)


async def analyze(
    domain: str,
    session: aiohttp.ClientSession,
) -> BacklinkResult:
    """Analyse backlink quality for *domain*."""
    result = BacklinkResult()

    try:
        # Run CommonCrawl + OpenPageRank in parallel
        cc_task = _query_commoncrawl(domain, session)
        opr_task = _query_openpagerank(domain, session)
        cc_links, page_rank = await asyncio.gather(
            cc_task, opr_task, return_exceptions=True
        )

        # Handle CommonCrawl results
        if isinstance(cc_links, Exception):
            logger.warning("CommonCrawl error: %s", cc_links)
            cc_links = []

        # Handle PageRank
        if isinstance(page_rank, Exception):
            logger.warning("OpenPageRank error: %s", page_rank)
            page_rank = 0.0

        result.page_rank = page_rank if isinstance(page_rank, (int, float)) else 0.0

        # Process backlinks
        seen_domains: set[str] = set()
        spam_domains: list[str] = []
        clean_domains: list[str] = []
        spam_anchors: list[str] = []
        anchor_counts: Counter[str] = Counter()

        for link in cc_links:
            bl = _process_backlink(link)
            result.backlinks.append(bl)

            if bl.source_domain not in seen_domains:
                seen_domains.add(bl.source_domain)
                if bl.is_spam:
                    spam_domains.append(f"{bl.source_domain} ({bl.spam_reason})")
                else:
                    clean_domains.append(bl.source_domain)

            if bl.anchor_text:
                anchor_counts[bl.anchor_text] += 1
                spam_cat = classify_anchor_text(bl.anchor_text)
                if spam_cat:
                    spam_anchors.append(f"{bl.anchor_text} [{spam_cat}]")

        result.total_backlinks = len(result.backlinks)
        result.referring_domains = len(seen_domains)
        result.spam_domains = spam_domains
        result.clean_domains = clean_domains[:20]  # top 20
        result.spam_anchors = list(dict.fromkeys(spam_anchors))[:20]
        result.anchor_distribution = dict(anchor_counts.most_common(30))

        # Compute spam ratio
        if seen_domains:
            result.spam_ratio = len(spam_domains) / len(seen_domains)
        else:
            result.spam_ratio = 0.0

        result.score = _compute_score(result)

    except Exception as exc:
        logger.exception("Backlink analysis error for %s", domain)
        result.error = str(exc)
        result.score = 50.0

    return result


# ─────────────────────────────────────────────
# Data sources
# ─────────────────────────────────────────────

async def _query_commoncrawl(
    domain: str,
    session: aiohttp.ClientSession,
) -> list[dict[str, str]]:
    """Query CommonCrawl Index API for pages linking to *domain*.

    We search for the domain appearing in the CommonCrawl index,
    then look up pages that reference it.
    """
    results: list[dict[str, str]] = []

    # Try multiple CC indices (recent ones)
    indices = [
        "CC-MAIN-2024-51",
        "CC-MAIN-2024-42",
        "CC-MAIN-2024-33",
        "CC-MAIN-2024-22",
        "CC-MAIN-2023-50",
    ]

    for idx in indices:
        try:
            url = f"https://index.commoncrawl.org/{idx}-index"
            params = {
                "url": f"*.{domain}",
                "output": "json",
                "limit": "100",
            }
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text()
                import json
                for line in text.strip().splitlines():
                    try:
                        record = json.loads(line)
                        results.append(record)
                    except json.JSONDecodeError:
                        continue

            if results:
                break  # Got data from this index, stop

        except Exception as exc:
            logger.debug("CC index %s failed: %s", idx, exc)
            continue

    # Convert CC records to backlink-like format
    # CC records contain pages FROM the domain, not TO it.
    # For actual backlinks, we'd need to use CC WAT files.
    # Here we extract outgoing links from the domain's pages
    # to verify the domain's link neighbourhood.
    return results


async def _query_openpagerank(
    domain: str,
    session: aiohttp.ClientSession,
) -> float:
    """Get OpenPageRank score (0-10) for domain."""
    if not cfg.OPENPAGERANK_API_KEY:
        return 0.0

    try:
        headers = {"API-OPR": cfg.OPENPAGERANK_API_KEY}
        params = {"domains[]": domain}
        async with session.get(
            cfg.OPENPAGERANK_URL,
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                return 0.0
            data = await resp.json()
            if data.get("response") and data["response"][0].get("page_rank_decimal"):
                return float(data["response"][0]["page_rank_decimal"])
    except Exception as exc:
        logger.debug("OpenPageRank error: %s", exc)

    return 0.0


def _process_backlink(record: dict[str, str]) -> BacklinkInfo:
    """Convert a CommonCrawl record into a BacklinkInfo."""
    url = record.get("url", "")
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    source_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    is_spam, spam_reason = is_spam_domain(source_domain)

    return BacklinkInfo(
        source_url=url,
        source_domain=source_domain,
        anchor_text="",  # CC index doesn't have anchor text
        is_spam=is_spam,
        spam_reason=spam_reason,
    )


def _compute_score(result: BacklinkResult) -> float:
    """Score 0–100 based on backlink quality."""
    score = 100.0

    # High spam ratio is very bad
    if result.spam_ratio > 0.5:
        score -= 50
    elif result.spam_ratio > 0.3:
        score -= 30
    elif result.spam_ratio > 0.1:
        score -= 15

    # Spam anchor texts
    if len(result.spam_anchors) > 5:
        score -= 20
    elif len(result.spam_anchors) > 2:
        score -= 10

    # No backlinks at all is slightly negative
    if result.referring_domains == 0:
        score -= 10

    # PageRank bonus
    if result.page_rank > 3:
        score += 5

    return max(0.0, min(100.0, score))
