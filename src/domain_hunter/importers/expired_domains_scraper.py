"""ExpiredDomains.net auto-scraper.

Requires a session cookie (PHPSESSID) from a logged-in browser session.
Set via .env: EXPIRED_DOMAINS_PHPSESSID=xxxxxxxxxxxx

How to get the cookie:
  1. Log in to https://www.expireddomains.net/
  2. Open browser DevTools → Application → Cookies
  3. Copy the value of PHPSESSID
  4. Paste it in .env
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import urlencode

import aiohttp
from bs4 import BeautifulSoup

from domain_hunter import config as cfg
from domain_hunter.models import DomainCandidate
from domain_hunter.profiles import NicheProfile

logger = logging.getLogger(__name__)

# ── ExpiredDomains.net URL patterns ──────────
_BASE_URL = "https://www.expireddomains.net"
_SEARCH_PATHS = {
    "deleted": "/expired-domains/",
    "expired": "/pending-delete-com-domains/",
    "backorder": "/backorder-domains/",
}

# TLD filter parameter mapping
_TLD_PARAMS = {
    "com": "ftlds[]=2", "net": "ftlds[]=3", "org": "ftlds[]=4",
    "info": "ftlds[]=5", "biz": "ftlds[]=6", "co": "ftlds[]=10",
    "io": "ftlds[]=36", "dev": "ftlds[]=100", "tw": "ftlds[]=200",
}


async def scrape_expired_domains(
    profile: NicheProfile,
    session_cookie: str,
    max_pages: int = 5,
    max_results: int = 200,
    search_type: str = "deleted",
) -> list[DomainCandidate]:
    """Scrape ExpiredDomains.net and return matching DomainCandidates.

    Args:
        profile: The niche profile with search keywords and filters.
        session_cookie: PHPSESSID value from a logged-in browser session.
        max_pages: Maximum pages to scrape per keyword group.
        max_results: Maximum total results to return.
        search_type: One of 'deleted', 'expired', 'backorder'.

    Returns:
        List of DomainCandidate objects, deduplicated.
    """
    if not session_cookie:
        logger.warning("No ExpiredDomains session cookie provided")
        return []

    search_path = _SEARCH_PATHS.get(search_type, _SEARCH_PATHS["deleted"])
    all_candidates: dict[str, DomainCandidate] = {}

    # Build keyword groups (search 2-3 keywords at a time)
    kw_groups = _build_keyword_groups(profile.search_keywords, group_size=3)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": f"{_BASE_URL}/",
    }
    cookies = {"PHPSESSID": session_cookie}

    connector = aiohttp.TCPConnector(limit=2)  # be gentle
    timeout = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout,
        headers=headers, cookies=cookies,
    ) as session:
        for group_idx, kw_group in enumerate(kw_groups):
            if len(all_candidates) >= max_results:
                break

            query = "+".join(kw_group)
            logger.info("Searching ExpiredDomains: %s", query)

            for page in range(max_pages):
                if len(all_candidates) >= max_results:
                    break

                params = _build_search_params(profile, query, page)
                url = f"{_BASE_URL}{search_path}?{params}"

                try:
                    async with session.get(url) as resp:
                        if resp.status == 403:
                            logger.error(
                                "ExpiredDomains returned 403 — session cookie "
                                "may be expired. Please update EXPIRED_DOMAINS_PHPSESSID."
                            )
                            return list(all_candidates.values())

                        if resp.status != 200:
                            logger.warning("HTTP %d for %s", resp.status, url)
                            break

                        html = await resp.text()
                        candidates = _parse_results_page(html)

                        if not candidates:
                            break  # no more results

                        for c in candidates:
                            if c.domain not in all_candidates:
                                c.source = "expireddomains"
                                all_candidates[c.domain] = c

                        logger.info(
                            "  Page %d: found %d domains (total: %d)",
                            page + 1, len(candidates), len(all_candidates),
                        )

                except Exception as exc:
                    logger.warning("Scrape error: %s", exc)
                    break

                # Rate limiting — be polite
                await asyncio.sleep(2.5)

            # Pause between keyword groups
            if group_idx < len(kw_groups) - 1:
                await asyncio.sleep(3)

    result = list(all_candidates.values())[:max_results]
    logger.info("ExpiredDomains scraper: total %d candidates", len(result))
    return result


def _build_keyword_groups(keywords: list[str], group_size: int = 3) -> list[list[str]]:
    """Split keywords into groups for multi-query search."""
    groups = []
    for i in range(0, len(keywords), group_size):
        groups.append(keywords[i : i + group_size])
    return groups


def _build_search_params(
    profile: NicheProfile,
    query: str,
    page: int,
) -> str:
    """Build URL query string for ExpiredDomains.net search."""
    params: dict[str, str] = {
        "q": query,
        "start": str(page * 25),  # 25 results per page
    }

    # TLD filter
    tld_parts = []
    for tld in profile.preferred_tlds:
        if tld in _TLD_PARAMS:
            tld_parts.append(_TLD_PARAMS[tld])

    # Domain age filter (using Archive.org birth year)
    if profile.aby_before:
        params["faby"] = f"1_{profile.aby_before}"

    # Domain Pop filter (referring domains)
    if profile.max_dp:
        params["fdp"] = f"1_{profile.max_dp}"

    # Sort by Domain Pop descending (get ones with some backlinks first)
    params["o"] = "domainpop"
    params["r"] = "d"

    # WHOIS available
    params["fwhois"] = "22"  # available for registration

    base = urlencode(params)
    if tld_parts:
        base += "&" + "&".join(tld_parts)

    return base


def _parse_results_page(html: str) -> list[DomainCandidate]:
    """Parse an ExpiredDomains results page HTML into candidates."""
    soup = BeautifulSoup(html, "lxml")
    candidates: list[DomainCandidate] = []

    # Find the results table
    table = soup.find("table", class_="base1")
    if not table:
        return []

    rows = table.find_all("tr", class_=re.compile(r"base\d"))
    for row in rows:
        try:
            cells = row.find_all("td")
            if len(cells) < 5:
                continue

            # Domain name is in the first cell
            domain_link = cells[0].find("a", class_="namemark")
            if not domain_link:
                domain_link = cells[0].find("a")
            if not domain_link:
                continue

            domain = domain_link.get_text(strip=True).lower()
            if not domain or "." not in domain:
                continue

            # Parse metrics from subsequent cells
            # Column order varies, but common layout:
            # Domain | BL | DP | ABY | WBY | Age | ...
            bl = _safe_int(cells, 1)
            dp = _safe_int(cells, 2)
            aby = _safe_int(cells, 3)
            wby = _safe_int(cells, 4)
            age = _safe_int(cells, 5) if len(cells) > 5 else 0

            import tldextract
            ext = tldextract.extract(domain)

            candidates.append(DomainCandidate(
                domain=domain,
                tld=ext.suffix,
                bl=bl,
                dp=dp,
                aby=aby,
                wby=wby,
                age=age,
                source="expireddomains",
            ))

        except Exception:
            continue

    return candidates


def _safe_int(cells: list, idx: int) -> int:
    """Safely extract integer from a table cell."""
    try:
        if idx >= len(cells):
            return 0
        text = cells[idx].get_text(strip=True)
        text = re.sub(r"[^\d\-]", "", text)
        return int(text) if text else 0
    except (ValueError, IndexError):
        return 0
