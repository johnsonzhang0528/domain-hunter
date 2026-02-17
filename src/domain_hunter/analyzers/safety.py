"""Safety / blacklist checks — Google Safe Browsing, URLhaus, VirusTotal."""

from __future__ import annotations

import logging

import aiohttp

from domain_hunter import config as cfg
from domain_hunter.models import SafetyResult

logger = logging.getLogger(__name__)


async def analyze(
    domain: str,
    session: aiohttp.ClientSession,
) -> SafetyResult:
    """Run all available safety checks for *domain*."""
    result = SafetyResult()

    checks = []
    checks.append(_check_urlhaus(domain, session))

    if cfg.GOOGLE_SAFE_BROWSING_KEY:
        checks.append(_check_safe_browsing(domain, session))

    if cfg.VIRUSTOTAL_API_KEY:
        checks.append(_check_virustotal(domain, session))

    import asyncio
    outcomes = await asyncio.gather(*checks, return_exceptions=True)

    for outcome in outcomes:
        if isinstance(outcome, Exception):
            logger.warning("Safety check error: %s", outcome)
            continue
        if outcome is None:
            continue

        source, is_flagged, details = outcome
        if is_flagged:
            result.is_safe = False
            if source == "safe_browsing":
                result.malware_flags.extend(details)
            elif source == "urlhaus":
                result.malware_flags.extend(details)
            elif source == "virustotal":
                result.malware_flags.extend(details)
            result.blacklisted_on.append(source)

    result.score = _compute_score(result)
    return result


async def _check_urlhaus(
    domain: str,
    session: aiohttp.ClientSession,
) -> tuple[str, bool, list[str]] | None:
    """Check abuse.ch URLhaus (free, no API key)."""
    try:
        data = aiohttp.FormData()
        data.add_field("host", domain)

        async with session.post(
            cfg.URLHAUS_URL,
            data=data,
            timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                return None
            result = await resp.json(content_type=None)

            if result.get("query_status") == "no_results":
                return ("urlhaus", False, [])

            urls = result.get("urls", [])
            if urls:
                tags = set()
                for u in urls[:10]:
                    for tag in u.get("tags", []) or []:
                        tags.add(tag)
                return ("urlhaus", True, [f"URLhaus: {', '.join(tags) or 'flagged'}"])

            return ("urlhaus", False, [])

    except Exception as exc:
        logger.debug("URLhaus error: %s", exc)
        return None


async def _check_safe_browsing(
    domain: str,
    session: aiohttp.ClientSession,
) -> tuple[str, bool, list[str]] | None:
    """Check Google Safe Browsing API v4."""
    try:
        payload = {
            "client": {"clientId": "domain-hunter", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{domain}/"},
                    {"url": f"https://{domain}/"},
                ],
            },
        }

        params = {"key": cfg.GOOGLE_SAFE_BROWSING_KEY}
        async with session.post(
            cfg.SAFE_BROWSING_URL,
            json=payload,
            params=params,
            timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()

            matches = data.get("matches", [])
            if matches:
                flags = [m.get("threatType", "unknown") for m in matches]
                return ("safe_browsing", True, [f"Google Safe Browsing: {', '.join(flags)}"])

            return ("safe_browsing", False, [])

    except Exception as exc:
        logger.debug("Safe Browsing error: %s", exc)
        return None


async def _check_virustotal(
    domain: str,
    session: aiohttp.ClientSession,
) -> tuple[str, bool, list[str]] | None:
    """Check VirusTotal domain report (free tier: 4 req/min)."""
    try:
        headers = {"x-apikey": cfg.VIRUSTOTAL_API_KEY}
        url = cfg.VIRUSTOTAL_URL.format(domain=domain)

        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()

            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                return (
                    "virustotal",
                    True,
                    [f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections"],
                )

            return ("virustotal", False, [])

    except Exception as exc:
        logger.debug("VirusTotal error: %s", exc)
        return None


def _compute_score(result: SafetyResult) -> float:
    """Score 0–100 based on safety."""
    if not result.is_safe:
        # Severe penalty for blacklisted domains
        penalty = len(result.blacklisted_on) * 30
        return max(0.0, 100.0 - penalty)

    return 100.0
