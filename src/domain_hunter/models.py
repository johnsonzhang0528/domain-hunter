"""Data models used across the entire pipeline."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    BUY = "BUY"
    MAYBE = "MAYBE"
    REJECT = "REJECT"


# ──────────────────────────────────────────────
# Input
# ──────────────────────────────────────────────
@dataclass
class DomainCandidate:
    """A single expired domain retrieved from a CSV or other source."""

    domain: str
    tld: str = ""
    bl: int = 0  # backlink count (from source)
    dp: int = 0  # domain pop / referring domains (from source)
    aby: int = 0  # Archive.org birth year
    wby: int = 0  # WHOIS birth year
    age: int = 0  # domain age in years
    source: str = "manual"
    raw: dict[str, Any] = field(default_factory=dict)


# ──────────────────────────────────────────────
# Analyzer outputs
# ──────────────────────────────────────────────
@dataclass
class WaybackSnapshot:
    """One snapshot from the Wayback Machine."""

    timestamp: str
    url: str
    status_code: int = 200
    title: str = ""
    meta_description: str = ""
    body_text_preview: str = ""
    language: str = ""
    detected_categories: list[str] = field(default_factory=list)


@dataclass
class WaybackResult:
    """Aggregated Wayback Machine analysis."""

    first_seen: str = ""
    last_seen: str = ""
    total_snapshots: int = 0
    snapshot_years: list[int] = field(default_factory=list)
    snapshots_analyzed: list[WaybackSnapshot] = field(default_factory=list)
    detected_categories: list[str] = field(default_factory=list)
    spam_flags: list[str] = field(default_factory=list)
    sample_titles: list[str] = field(default_factory=list)
    languages_detected: list[str] = field(default_factory=list)
    score: float = 0.0
    error: str = ""


@dataclass
class BacklinkInfo:
    """A single backlink record."""

    source_url: str
    source_domain: str
    anchor_text: str = ""
    is_spam: bool = False
    spam_reason: str = ""


@dataclass
class BacklinkResult:
    """Backlink quality analysis."""

    total_backlinks: int = 0
    referring_domains: int = 0
    spam_ratio: float = 0.0
    spam_domains: list[str] = field(default_factory=list)
    spam_anchors: list[str] = field(default_factory=list)
    clean_domains: list[str] = field(default_factory=list)
    anchor_distribution: dict[str, int] = field(default_factory=dict)
    backlinks: list[BacklinkInfo] = field(default_factory=list)
    page_rank: float = 0.0
    score: float = 0.0
    error: str = ""


@dataclass
class DnsResult:
    """DNS resolution result."""

    is_registered: bool = False
    has_a_record: bool = False
    has_ns_record: bool = False
    a_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    is_parked: bool = False
    parking_provider: str = ""
    score: float = 0.0
    error: str = ""


@dataclass
class WhoisResult:
    """WHOIS lookup result."""

    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    is_available: bool = False
    age_years: int = 0
    score: float = 0.0
    error: str = ""


@dataclass
class SafetyResult:
    """Safety / blacklist check result."""

    is_safe: bool = True
    blacklisted_on: list[str] = field(default_factory=list)
    malware_flags: list[str] = field(default_factory=list)
    phishing_flags: list[str] = field(default_factory=list)
    spam_db_hits: list[str] = field(default_factory=list)
    score: float = 100.0
    error: str = ""


# ──────────────────────────────────────────────
# Final report
# ──────────────────────────────────────────────
@dataclass
class DomainReport:
    """Final comprehensive report for a domain candidate."""

    domain: str
    candidate: DomainCandidate
    wayback: WaybackResult = field(default_factory=WaybackResult)
    backlinks: BacklinkResult = field(default_factory=BacklinkResult)
    dns: DnsResult = field(default_factory=DnsResult)
    whois: WhoisResult = field(default_factory=WhoisResult)
    safety: SafetyResult = field(default_factory=SafetyResult)
    total_score: float = 0.0
    verdict: Verdict = Verdict.REJECT
    rejection_reasons: list[str] = field(default_factory=list)
    positive_signals: list[str] = field(default_factory=list)
    analyzed_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
    )
