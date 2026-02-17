"""Centralised configuration & constants."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ── Paths ────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"
OUTPUT_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR = Path(__file__).resolve().parent / "reports" / "templates"

# ── API Keys (all optional) ──────────────────
OPENPAGERANK_API_KEY: str = os.getenv("OPENPAGERANK_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
AHREFS_API_KEY: str = os.getenv("AHREFS_API_KEY", "")

# ── Runtime tuning ───────────────────────────
WAYBACK_MAX_SNAPSHOTS: int = int(os.getenv("WAYBACK_MAX_SNAPSHOTS", "10"))
MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "5"))
REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "30"))

# ── Wayback Machine ─────────────────────────
WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_FETCH_URL = "https://web.archive.org/web/{ts}id_/{url}"

# ── CommonCrawl ──────────────────────────────
CC_INDEX_URL = "https://index.commoncrawl.org/CC-MAIN-2024-51-index"

# ── OpenPageRank ─────────────────────────────
OPENPAGERANK_URL = "https://openpagerank.com/api/v1.0/getPageRank"

# ── Google Safe Browsing ─────────────────────
SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

# ── VirusTotal ───────────────────────────────
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

# ── URLhaus (abuse.ch — 免費) ────────────────
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"

# ──────────────────────────────────────────────
# Spam / Adult / Gambling keyword dictionaries
# ──────────────────────────────────────────────
SPAM_KEYWORDS: set[str] = {
    # Gambling
    "casino", "poker", "bet", "betting", "gamble", "gambling",
    "slot", "slots", "blackjack", "roulette", "sportsbook", "baccarat",
    "lottery", "jackpot", "wager",
    # Adult
    "porn", "xxx", "adult", "sex", "escort", "nude", "naked",
    "cam girl", "webcam", "onlyfans", "hentai", "erotic",
    # Pharma spam
    "viagra", "cialis", "pharmacy", "pills", "xanax", "tramadol",
    "phentermine", "hydrocodone", "oxycodone", "modafinil",
    # SEO spam / PBN
    "buy backlinks", "cheap seo", "link building service",
    "private blog network", "pbn",
    # Malware / warez
    "crack", "keygen", "warez", "torrent", "pirate",
    "free download", "nulled", "activator",
}

# Spam TLDs (domains from these TLDs linking in are suspicious)
SPAM_TLDS: set[str] = {
    "xyz", "top", "click", "loan", "gdn", "icu", "buzz",
    "surf", "monster", "rest", "cyou", "cfd", "sbs",
    "beauty", "hair", "quest", "bond", "lol",
}

# Known parking / redirect providers
PARKING_PROVIDERS: set[str] = {
    "sedoparking", "hugedomains", "godaddy", "dan.com",
    "afternic", "dropcatch", "snapnames", "namejet",
    "bodis", "above.com", "parkingcrew",
}

# Positive niche keywords (for our use case: travel / culture / outdoors)
NICHE_KEYWORDS: set[str] = {
    "travel", "tourism", "tour", "trip", "journey", "adventure",
    "outdoor", "camping", "hiking", "nature", "trail", "backpack",
    "temple", "culture", "heritage", "worship", "blessing", "shrine",
    "taiwan", "asia", "island", "scenic", "landscape",
    "hotel", "hostel", "accommodation", "resort",
    "food", "cuisine", "restaurant", "recipe",
    "guide", "itinerary", "destination", "explore",
}

# ── Scoring weights (total = 100) ────────────
SCORE_WEIGHTS = {
    "wayback": 30,       # Historical content cleanliness
    "backlinks": 25,     # Backlink quality
    "safety": 15,        # Blacklist / malware check
    "niche_relevance": 15,  # Relevance to target niche
    "domain_age": 10,    # Age bonus
    "dns_availability": 5,  # Is it actually available?
}

# Verdict thresholds
VERDICT_THRESHOLDS = {
    "buy": 75,
    "maybe": 50,
}
