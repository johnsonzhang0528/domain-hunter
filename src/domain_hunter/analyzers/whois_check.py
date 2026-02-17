"""WHOIS lookup and domain age analysis."""

from __future__ import annotations

import datetime as _dt
import logging

import whois  # python-whois

from domain_hunter.models import WhoisResult

logger = logging.getLogger(__name__)


def analyze(domain: str) -> WhoisResult:
    """Look up WHOIS info for *domain*."""
    result = WhoisResult()

    try:
        w = whois.whois(domain)

        if w is None or w.domain_name is None:
            result.is_available = True
            result.score = 100.0
            return result

        # Registrar
        result.registrar = str(w.registrar or "")

        # Dates — python-whois sometimes returns lists
        result.creation_date = _fmt_date(w.creation_date)
        result.expiration_date = _fmt_date(w.expiration_date)
        result.updated_date = _fmt_date(w.updated_date)

        # Name servers
        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                result.name_servers = [str(n).lower() for n in ns if n]
            else:
                result.name_servers = [str(ns).lower()]

        # Status
        status = w.status
        if status:
            if isinstance(status, list):
                result.status = [str(s) for s in status]
            else:
                result.status = [str(status)]

        # Domain age
        creation = _parse_date(w.creation_date)
        if creation:
            now = _dt.datetime.now(_dt.timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=_dt.timezone.utc)
            age = (now - creation).days / 365.25
            result.age_years = int(age)

        # Availability check
        if any("pendingDelete" in s.lower() for s in result.status):
            result.is_available = True
        elif any("redemptionPeriod" in s for s in result.status):
            result.is_available = False  # still in redemption

        result.score = _compute_score(result)

    except Exception as exc:
        err_str = str(exc).lower()
        if "no match" in err_str or "not found" in err_str or "no whois" in err_str:
            result.is_available = True
            result.score = 90.0
            return result
        logger.warning("WHOIS error for %s: %s", domain, exc)
        result.error = str(exc)
        result.score = 50.0

    return result


def _fmt_date(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, _dt.datetime):
        return val.strftime("%Y-%m-%d")
    if isinstance(val, _dt.date):
        return val.strftime("%Y-%m-%d")
    return str(val)


def _parse_date(val) -> _dt.datetime | None:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, _dt.datetime):
        return val
    if isinstance(val, _dt.date):
        return _dt.datetime.combine(val, _dt.time.min)
    return None


def _compute_score(result: WhoisResult) -> float:
    """Score based on WHOIS findings."""
    score = 70.0

    # Older domains get bonus
    if result.age_years >= 10:
        score += 20
    elif result.age_years >= 5:
        score += 10
    elif result.age_years >= 2:
        score += 5

    # Available for registration is great
    if result.is_available:
        score += 10

    return max(0.0, min(100.0, score))
