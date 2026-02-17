"""Niche profiles — pre-defined search configurations for common project themes.

Each profile defines:
  - search keywords for ExpiredDomains.net
  - preferred TLDs
  - domain name keywords (positive & negative)
  - content relevance keywords
  - pre-filter criteria
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NicheProfile:
    """A niche profile defines the ideal expired domain characteristics."""

    name: str
    description: str

    # Keywords to search on ExpiredDomains.net (OR logic)
    search_keywords: list[str] = field(default_factory=list)

    # Preferred TLDs (ordered by preference)
    preferred_tlds: list[str] = field(default_factory=list)

    # Keywords that SHOULD appear in the domain name (bonus points)
    domain_positive_keywords: list[str] = field(default_factory=list)

    # Keywords that must NOT appear in the domain name (instant reject)
    domain_negative_keywords: list[str] = field(default_factory=list)

    # Content keywords for Wayback Machine relevance check
    content_keywords: list[str] = field(default_factory=list)

    # ── Pre-filter thresholds ────────────────
    min_age: int = 2              # minimum domain age (years)
    max_age: int = 25             # maximum domain age (years)
    min_dp: int = 0               # minimum referring domains (Domain Pop)
    max_dp: int = 200             # maximum (too many = likely spammed)
    min_bl: int = 0               # minimum backlinks
    max_bl: int = 10000           # maximum backlinks
    max_domain_length: int = 25   # domain name max chars (excl. TLD)
    aby_before: int = 2020        # Archive birth year should be before
    require_english_chars: bool = True  # domain must be ASCII only


# ═══════════════════════════════════════════════
# Built-in Profiles
# ═══════════════════════════════════════════════

PROFILES: dict[str, NicheProfile] = {}


def _register(p: NicheProfile) -> None:
    PROFILES[p.name] = p


# ── 1. 戶外旅遊 (Outdoor / Travel) ──────────
_register(NicheProfile(
    name="outdoor-travel",
    description="戶外露營 / 旅遊 / 健行 / 自然探索",
    search_keywords=[
        "travel", "outdoor", "camping", "hiking",
        "adventure", "nature", "backpack", "trail",
        "tourism", "explore", "journey", "scenic",
        "trek", "wanderlust", "expedition",
    ],
    preferred_tlds=["com", "net", "org", "co"],
    domain_positive_keywords=[
        "travel", "tour", "trip", "outdoor", "camp",
        "hike", "nature", "trail", "adventure", "explore",
        "wander", "trek", "journey", "scenic", "wild",
        "backpack", "guide", "discover",
    ],
    domain_negative_keywords=[
        "casino", "poker", "bet", "slot", "porn", "xxx",
        "adult", "sex", "viagra", "pharma", "crack", "warez",
        "loan", "debt", "forex", "crypto", "nft", "token",
        "cheap", "free", "buy", "deal", "coupon",
    ],
    content_keywords=[
        "travel", "tourism", "outdoor", "camping", "hiking",
        "nature", "trail", "adventure", "backpack", "hotel",
        "hostel", "resort", "destination", "itinerary",
        "guide", "scenic", "landscape", "explore",
    ],
    min_age=3,
    max_dp=150,
    max_domain_length=22,
    aby_before=2018,
))

# ── 2. 台灣文化 / 廟宇 ──────────────────────
_register(NicheProfile(
    name="taiwan-culture",
    description="台灣文化 / 廟宇 / 宗教 / 民俗",
    search_keywords=[
        "temple", "taiwan", "culture", "heritage",
        "shrine", "worship", "blessing", "festival",
        "tradition", "folk", "religion", "asia",
    ],
    preferred_tlds=["com", "org", "net", "tw"],
    domain_positive_keywords=[
        "temple", "taiwan", "culture", "shrine", "worship",
        "blessing", "heritage", "tradition", "festival",
        "spirit", "sacred", "faith", "asia", "folk",
    ],
    domain_negative_keywords=[
        "casino", "poker", "bet", "slot", "porn", "xxx",
        "adult", "sex", "viagra", "pharma", "crack",
        "loan", "debt", "forex", "crypto",
    ],
    content_keywords=[
        "temple", "worship", "culture", "taiwan", "shrine",
        "religion", "buddhism", "taoism", "festival",
        "heritage", "tradition", "blessing", "prayer",
    ],
    min_age=2,
    max_dp=120,
    aby_before=2019,
))

# ── 3. 美食 / 食譜 ──────────────────────────
_register(NicheProfile(
    name="food-recipe",
    description="美食 / 食譜 / 餐廳 / 烹飪",
    search_keywords=[
        "food", "recipe", "cook", "cuisine", "restaurant",
        "kitchen", "meal", "dish", "bake", "grill",
        "healthy", "diet", "nutrition", "delicious",
    ],
    preferred_tlds=["com", "net", "org", "co"],
    domain_positive_keywords=[
        "food", "recipe", "cook", "cuisine", "kitchen",
        "meal", "dish", "bake", "grill", "eat",
        "yummy", "delicious", "tasty", "chef",
    ],
    domain_negative_keywords=[
        "casino", "poker", "bet", "porn", "xxx", "adult",
        "viagra", "pharma", "crack", "warez",
        "loan", "forex", "crypto",
    ],
    content_keywords=[
        "recipe", "food", "cooking", "ingredient", "cuisine",
        "restaurant", "kitchen", "meal", "dish", "nutrition",
    ],
    min_age=2,
    max_dp=150,
))

# ── 4. 科技 / 部落格 ────────────────────────
_register(NicheProfile(
    name="tech-blog",
    description="科技 / 程式 / 軟體 / 部落格",
    search_keywords=[
        "tech", "code", "software", "developer", "programming",
        "blog", "digital", "web", "app", "startup",
        "gadget", "innovation", "tutorial",
    ],
    preferred_tlds=["com", "io", "dev", "net", "org"],
    domain_positive_keywords=[
        "tech", "code", "dev", "software", "digital",
        "web", "app", "blog", "hack", "byte",
        "pixel", "stack", "geek", "nerd", "lab",
    ],
    domain_negative_keywords=[
        "casino", "poker", "bet", "porn", "xxx", "adult",
        "viagra", "pharma", "crack", "warez",
        "loan", "forex",
    ],
    content_keywords=[
        "technology", "software", "programming", "code",
        "developer", "tutorial", "web", "app", "startup",
        "digital", "computer", "internet",
    ],
    min_age=2,
    max_dp=200,
))

# ── 5. 通用 (General — AdSense 友好) ────────
_register(NicheProfile(
    name="general",
    description="通用型 — 適合 AdSense 的乾淨域名",
    search_keywords=[
        "guide", "info", "tips", "life", "daily",
        "world", "hub", "zone", "spot", "point",
    ],
    preferred_tlds=["com", "net", "org"],
    domain_positive_keywords=[
        "guide", "info", "tips", "life", "world",
        "hub", "daily", "zone", "spot", "point",
        "best", "top", "smart", "easy",
    ],
    domain_negative_keywords=[
        "casino", "poker", "bet", "slot", "porn", "xxx",
        "adult", "sex", "viagra", "pharma", "crack", "warez",
        "loan", "debt", "forex", "crypto", "nft",
    ],
    content_keywords=[],
    min_age=2,
    max_dp=120,
))


def get_profile(name: str) -> NicheProfile:
    """Get a profile by name. Raises KeyError if not found."""
    if name not in PROFILES:
        available = ", ".join(sorted(PROFILES.keys()))
        raise KeyError(
            f"Unknown profile '{name}'. Available: {available}"
        )
    return PROFILES[name]


def list_profiles() -> list[tuple[str, str]]:
    """Return list of (name, description) for all profiles."""
    return [(p.name, p.description) for p in PROFILES.values()]
