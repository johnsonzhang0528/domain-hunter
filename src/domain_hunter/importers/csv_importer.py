"""Import domain candidates from CSV files (ExpiredDomains.net exports, etc.)."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import TextIO

import tldextract

from domain_hunter.models import DomainCandidate

# ── Column name mapping ──────────────────────
# ExpiredDomains.net uses different column names depending on export format.
# We normalise here.  Keys are lowercase+stripped versions of common headers.
_COL_MAP: dict[str, str] = {
    "domain": "domain",
    "domainname": "domain",
    "domain name": "domain",
    # Backlinks
    "bl": "bl",
    "backlinks": "bl",
    "totallinks": "bl",
    # Domain Pop (referring domains)
    "dp": "dp",
    "domainpop": "dp",
    "domain pop": "dp",
    "rd": "dp",
    "refdomains": "dp",
    "referring domains": "dp",
    # Archive birth year
    "aby": "aby",
    "archivebirthyear": "aby",
    "archive.org birth": "aby",
    "birth": "aby",
    # WHOIS birth year
    "wby": "wby",
    "whoisbirthyear": "wby",
    "creation year": "wby",
    # TLD
    "tld": "tld",
    "extension": "tld",
    # Age
    "age": "age",
    "domainage": "age",
}


def _normalise_header(h: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", h.lower()).strip()


def _safe_int(val: str) -> int:
    try:
        return int(re.sub(r"[^0-9\-]", "", str(val)))
    except (ValueError, TypeError):
        return 0


def parse_csv(source: str | Path | TextIO) -> list[DomainCandidate]:
    """Parse a CSV file into a list of DomainCandidate objects.

    Accepts:
      • file path (str or Path)
      • an already-opened file-like object
    """
    rows: list[dict[str, str]] = []

    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"CSV not found: {path}")
        for enc in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
            try:
                with open(path, newline="", encoding=enc) as fh:
                    reader = csv.DictReader(fh)
                    rows = list(reader)
                break
            except UnicodeDecodeError:
                continue
    else:
        reader = csv.DictReader(source)
        rows = list(reader)

    if not rows:
        return []

    # Build column look-up from actual headers
    header_map: dict[str, str] = {}
    for raw_h in rows[0].keys():
        norm = _normalise_header(raw_h)
        if norm in _COL_MAP:
            header_map[_COL_MAP[norm]] = raw_h

    if "domain" not in header_map:
        raise ValueError(
            "CSV must have a 'Domain' column.  "
            f"Found columns: {list(rows[0].keys())}"
        )

    candidates: list[DomainCandidate] = []
    seen: set[str] = set()

    for row in rows:
        domain = row.get(header_map["domain"], "").strip().lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)

        ext = tldextract.extract(domain)
        tld = row.get(header_map.get("tld", ""), "") or ext.suffix

        candidates.append(
            DomainCandidate(
                domain=domain,
                tld=tld,
                bl=_safe_int(row.get(header_map.get("bl", ""), "0")),
                dp=_safe_int(row.get(header_map.get("dp", ""), "0")),
                aby=_safe_int(row.get(header_map.get("aby", ""), "0")),
                wby=_safe_int(row.get(header_map.get("wby", ""), "0")),
                age=_safe_int(row.get(header_map.get("age", ""), "0")),
                source="csv",
                raw=dict(row),
            )
        )

    return candidates


def parse_domain_list(text: str) -> list[DomainCandidate]:
    """Parse a plain-text list of domains (one per line)."""
    candidates: list[DomainCandidate] = []
    seen: set[str] = set()

    for line in text.strip().splitlines():
        domain = line.strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/")[0]
        if not domain or domain in seen:
            continue
        seen.add(domain)

        ext = tldextract.extract(domain)
        candidates.append(
            DomainCandidate(
                domain=domain,
                tld=ext.suffix,
                source="manual",
            )
        )

    return candidates
