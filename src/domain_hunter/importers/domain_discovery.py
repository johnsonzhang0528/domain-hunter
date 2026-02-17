"""Multi-source domain discovery — free alternatives when scraping isn't available.

Sources:
  1. ExpiredDomains.net scraper (if session cookie available)
  2. Domain name generation from niche keywords + availability check
  3. Web.archive.org CDX search for abandoned domains
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import random
import re
from typing import Any

import aiohttp

from domain_hunter import config as cfg
from domain_hunter.models import DomainCandidate
from domain_hunter.profiles import NicheProfile

logger = logging.getLogger(__name__)

# Prefixes and suffixes for creative domain generation
_PREFIXES = [
    "my", "the", "go", "get", "try", "top", "best", "pro",
    "all", "one", "ez", "smart", "daily", "real", "true",
]
_SUFFIXES = [
    "hub", "spot", "zone", "guide", "tips", "world", "life",
    "now", "ly", "er", "ful", "ify", "lab", "hq", "base",
    "nest", "path", "way", "wise", "vine",
]


async def discover_domains(
    profile: NicheProfile,
    session_cookie: str = "",
    max_total: int = 100,
) -> list[DomainCandidate]:
    """Run all discovery sources and return deduplicated candidates.

    Discovery sources are run in priority order:
      1. ExpiredDomains.net scraper (if cookie provided)
      2. Keyword-combination domain generation + DNS availability check
      3. Wayback CDX search for dead domains in the niche
    """
    all_candidates: dict[str, DomainCandidate] = {}

    # ── Source 1: ExpiredDomains.net ──────────
    if session_cookie:
        from domain_hunter.importers.expired_domains_scraper import (
            scrape_expired_domains,
        )

        try:
            scraped = await scrape_expired_domains(
                profile=profile,
                session_cookie=session_cookie,
                max_results=max_total,
            )
            for c in scraped:
                all_candidates[c.domain] = c
            logger.info("ExpiredDomains: found %d candidates", len(scraped))
        except Exception as exc:
            logger.warning("ExpiredDomains scraper failed: %s", exc)

    # ── Source 2: keyword-based generation + availability ──
    remaining = max_total - len(all_candidates)
    if remaining > 0:
        generated = await _generate_and_check(profile, max_check=remaining * 5, max_available=remaining)
        for c in generated:
            if c.domain not in all_candidates:
                all_candidates[c.domain] = c
        logger.info("Domain generation: found %d available", len(generated))

    # ── Source 3: Wayback CDX dead domain search ──
    remaining = max_total - len(all_candidates)
    if remaining > 0:
        wayback_found = await _search_wayback_dead(profile, max_results=remaining)
        for c in wayback_found:
            if c.domain not in all_candidates:
                all_candidates[c.domain] = c
        logger.info("Wayback dead search: found %d candidates", len(wayback_found))

    result = list(all_candidates.values())[:max_total]
    logger.info("Total discovery: %d unique candidates", len(result))
    return result


async def _generate_and_check(
    profile: NicheProfile,
    max_check: int = 200,
    max_available: int = 50,
) -> list[DomainCandidate]:
    """Generate domain names from profile keywords and check availability via DNS."""
    import dns.resolver
    import dns.exception

    # Generate candidate domain names
    names = _generate_domain_names(profile, count=max_check)

    available: list[DomainCandidate] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # Check availability in batches
    batch_size = 20
    for i in range(0, len(names), batch_size):
        if len(available) >= max_available:
            break

        batch = names[i : i + batch_size]
        for domain in batch:
            if len(available) >= max_available:
                break

            try:
                resolver.resolve(domain, "A")
                # Got A record → domain is taken
                continue
            except dns.resolver.NXDOMAIN:
                # No DNS record → might be available!
                import tldextract
                ext = tldextract.extract(domain)
                available.append(DomainCandidate(
                    domain=domain,
                    tld=ext.suffix,
                    source="generated",
                ))
            except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.exception.DNSException):
                # Timeout/error → skip
                continue

        await asyncio.sleep(0.5)  # rate limit

    return available


def _generate_domain_names(profile: NicheProfile, count: int = 200) -> list[str]:
    """Generate creative domain names from profile keywords."""
    names: list[str] = []
    tlds = profile.preferred_tlds[:3] or ["com"]

    keywords = profile.domain_positive_keywords[:10]
    if not keywords:
        keywords = profile.search_keywords[:10]

    # Strategy 1: keyword + suffix
    for kw, sfx in itertools.product(keywords, _SUFFIXES):
        for tld in tlds:
            name = f"{kw}{sfx}.{tld}"
            if len(kw + sfx) <= profile.max_domain_length:
                names.append(name)

    # Strategy 2: prefix + keyword
    for pfx, kw in itertools.product(_PREFIXES, keywords):
        for tld in tlds:
            name = f"{pfx}{kw}.{tld}"
            if len(pfx + kw) <= profile.max_domain_length:
                names.append(name)

    # Strategy 3: two keywords combined
    for kw1, kw2 in itertools.combinations(keywords[:8], 2):
        for tld in tlds:
            names.append(f"{kw1}{kw2}.{tld}")
            names.append(f"{kw2}{kw1}.{tld}")

    # Shuffle to spread across strategies
    random.shuffle(names)

    # Remove duplicates while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for n in names:
        if n not in seen and len(n.split(".")[0]) <= profile.max_domain_length:
            seen.add(n)
            unique.append(n)

    return unique[:count]


async def _search_wayback_dead(
    profile: NicheProfile,
    max_results: int = 30,
) -> list[DomainCandidate]:
    """Search Wayback Machine CDX for domains in our niche that are now dead.

    Strategy: Search CDX for URLs matching niche keywords,
    then check if those domains are now available.
    """
    import dns.resolver
    import dns.exception

    candidates: list[DomainCandidate] = []
    search_keywords = profile.search_keywords[:5]

    connector = aiohttp.TCPConnector(limit=3)
    timeout = aiohttp.ClientTimeout(total=30)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; DomainHunter/1.0)"
    }

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=headers,
    ) as session:
        for kw in search_keywords:
            if len(candidates) >= max_results:
                break

            # Search CDX for domains containing this keyword
            try:
                params = {
                    "url": f"*{kw}*.com",
                    "output": "json",
                    "fl": "original",
                    "filter": "mimetype:text/html",
                    "collapse": "urlkey",
                    "limit": "50",
                }
                async with session.get(
                    cfg.WAYBACK_CDX_URL,
                    params=params,
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
                    if not data or len(data) < 2:
                        continue

                    # Extract unique domains
                    domains_found: set[str] = set()
                    import tldextract
                    for row in data[1:]:
                        url = row[0] if isinstance(row, list) else row.get("original", "")
                        ext = tldextract.extract(url)
                        domain = f"{ext.domain}.{ext.suffix}"
                        if (
                            ext.suffix in (profile.preferred_tlds or ["com"])
                            and len(ext.domain) <= profile.max_domain_length
                            and _passes_name_filter(ext.domain, profile)
                        ):
                            domains_found.add(domain)

                    # Check if these domains are now available
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3

                    for domain in list(domains_found)[:30]:
                        if len(candidates) >= max_results:
                            break
                        try:
                            resolver.resolve(domain, "A")
                        except dns.resolver.NXDOMAIN:
                            ext = tldextract.extract(domain)
                            candidates.append(DomainCandidate(
                                domain=domain,
                                tld=ext.suffix,
                                source="wayback_dead",
                            ))
                        except Exception:
                            continue

            except Exception as exc:
                logger.debug("Wayback dead search error for '%s': %s", kw, exc)

            await asyncio.sleep(1)

    return candidates


def _passes_name_filter(domain_name: str, profile: NicheProfile) -> bool:
    """Check if a domain name passes the profile's negative keyword filter."""
    name_lower = domain_name.lower()
    for neg_kw in profile.domain_negative_keywords:
        if neg_kw in name_lower:
            return False
    return True
