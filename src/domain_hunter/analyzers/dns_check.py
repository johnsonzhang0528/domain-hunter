"""DNS resolution and domain availability check."""

from __future__ import annotations

import logging

import dns.resolver
import dns.exception

from domain_hunter import config as cfg
from domain_hunter.models import DnsResult

logger = logging.getLogger(__name__)

# Known parking / redirect name servers
_PARKING_NS = {
    "ns1.sedoparking.com", "ns2.sedoparking.com",
    "ns1.bodis.com", "ns2.bodis.com",
    "ns1.above.com", "ns2.above.com",
    "ns1.parkingcrew.net", "ns2.parkingcrew.net",
    "ns1.hugedomains.com", "ns2.hugedomains.com",
    "ns1.afternic.com", "ns2.afternic.com",
    "sell.internettraffic.com",
    "park-ns1.dan.com",
}

# Known parking A records (common landing IPs)
_PARKING_IPS = {
    "52.1.0.0", "54.230.", "13.32.",  # partial matches for AWS CloudFront parking
    "98.124.199.",  # DomainSponsor
    "66.96.149.",   # Network Solutions parking
    "208.91.197.",  # Above.com
    "199.59.243.",  # Bodis
}


def analyze(domain: str) -> DnsResult:
    """Check DNS records for *domain*."""
    result = DnsResult()

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        # ── A records ──────────────────────────
        try:
            answers = resolver.resolve(domain, "A")
            result.a_records = [str(r) for r in answers]
            result.has_a_record = True
            result.is_registered = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.DNSException:
            pass

        # ── NS records ─────────────────────────
        try:
            answers = resolver.resolve(domain, "NS")
            result.ns_records = [str(r).rstrip(".").lower() for r in answers]
            result.has_ns_record = True
            result.is_registered = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.DNSException:
            pass

        # ── MX records ─────────────────────────
        try:
            answers = resolver.resolve(domain, "MX")
            result.mx_records = [str(r.exchange).rstrip(".") for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.DNSException:
            pass

        # ── Check if parked ────────────────────
        for ns in result.ns_records:
            if ns in _PARKING_NS:
                result.is_parked = True
                result.parking_provider = ns
                break

        if not result.is_parked and result.a_records:
            for ip in result.a_records:
                for parking_ip in _PARKING_IPS:
                    if ip.startswith(parking_ip):
                        result.is_parked = True
                        result.parking_provider = f"parking IP {ip}"
                        break

        # ── Score ──────────────────────────────
        result.score = _compute_score(result)

    except Exception as exc:
        logger.exception("DNS analysis error for %s", domain)
        result.error = str(exc)
        result.score = 50.0

    return result


def _compute_score(result: DnsResult) -> float:
    """Score 0–100 based on DNS findings.

    Higher score = better for acquisition.
    - Available (NXDOMAIN) = 100 (great, can register)
    - Parked = 60 (can potentially buy)
    - Active site = 20 (probably not truly expired)
    """
    if not result.is_registered:
        return 100.0  # available!

    if result.is_parked:
        return 60.0  # parked, might be purchasable

    if result.has_a_record and not result.is_parked:
        return 20.0  # active site, might not be available

    return 50.0  # ambiguous
