"""Pipeline orchestrator — coordinates all analyzers for batch domain evaluation."""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import aiohttp
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from domain_hunter import config as cfg
from domain_hunter.analyzers import backlinks, dns_check, safety, wayback, whois_check
from domain_hunter.models import DomainCandidate, DomainReport
from domain_hunter.scoring.scorer import compute_final_score

logger = logging.getLogger(__name__)
console = Console()

# Semaphore to limit concurrent HTTP connections
_SEM: asyncio.Semaphore | None = None


async def analyze_single(
    candidate: DomainCandidate,
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
) -> DomainReport:
    """Run all analyzers for a single domain candidate."""
    domain = candidate.domain
    report = DomainReport(domain=domain, candidate=candidate)

    async with sem:
        logger.info("Analyzing: %s", domain)

        # ── Async analyzers (HTTP-based) ─────
        wb_task = wayback.analyze(domain, session)
        bl_task = backlinks.analyze(domain, session)
        sf_task = safety.analyze(domain, session)

        wb_result, bl_result, sf_result = await asyncio.gather(
            wb_task, bl_task, sf_task, return_exceptions=True
        )

        if not isinstance(wb_result, Exception):
            report.wayback = wb_result
        else:
            logger.warning("Wayback error for %s: %s", domain, wb_result)

        if not isinstance(bl_result, Exception):
            report.backlinks = bl_result
        else:
            logger.warning("Backlink error for %s: %s", domain, bl_result)

        if not isinstance(sf_result, Exception):
            report.safety = sf_result
        else:
            logger.warning("Safety error for %s: %s", domain, sf_result)

        # ── Sync analyzers (run in thread pool) ──
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=2) as pool:
            dns_future = loop.run_in_executor(pool, dns_check.analyze, domain)
            whois_future = loop.run_in_executor(pool, whois_check.analyze, domain)

            dns_result, whois_result = await asyncio.gather(
                dns_future, whois_future, return_exceptions=True
            )

        if not isinstance(dns_result, Exception):
            report.dns = dns_result
        else:
            logger.warning("DNS error for %s: %s", domain, dns_result)

        if not isinstance(whois_result, Exception):
            report.whois = whois_result
        else:
            logger.warning("WHOIS error for %s: %s", domain, whois_result)

        # ── Compute final score ──────────────
        compute_final_score(report)

    return report


async def analyze_batch(
    candidates: list[DomainCandidate],
    max_concurrent: int | None = None,
) -> list[DomainReport]:
    """Analyze a batch of domain candidates with progress display.

    Returns a list of DomainReport sorted by total_score descending.
    """
    max_concurrent = max_concurrent or cfg.MAX_WORKERS
    sem = asyncio.Semaphore(max_concurrent)

    connector = aiohttp.TCPConnector(
        limit=max_concurrent * 3,
        ttl_dns_cache=300,
        force_close=False,
    )
    timeout = aiohttp.ClientTimeout(total=cfg.REQUEST_TIMEOUT * 3)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; DomainHunter/1.0; "
            "+https://github.com/johnsonzhang0528/domain-hunter)"
        )
    }

    reports: list[DomainReport] = []

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers,
    ) as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "分析域名中...",
                total=len(candidates),
            )

            tasks = []
            for candidate in candidates:
                tasks.append(
                    _analyze_with_progress(candidate, session, sem, progress, task)
                )

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    logger.error("Pipeline error: %s", r)
                    continue
                reports.append(r)

    # Sort by score descending
    reports.sort(key=lambda r: r.total_score, reverse=True)
    return reports


async def _analyze_with_progress(
    candidate: DomainCandidate,
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    progress: Progress,
    task_id,
) -> DomainReport:
    """Wrapper that updates progress bar after analysis."""
    report = await analyze_single(candidate, session, sem)
    progress.advance(task_id)
    return report


def run_pipeline(
    candidates: list[DomainCandidate],
    max_concurrent: int | None = None,
) -> list[DomainReport]:
    """Synchronous entry point — runs the async pipeline."""
    t0 = time.time()
    console.print(
        f"\n[bold green]🔍 Domain Hunter[/] — 開始分析 "
        f"[yellow]{len(candidates)}[/] 個域名\n"
    )

    reports = asyncio.run(analyze_batch(candidates, max_concurrent))

    elapsed = time.time() - t0
    console.print(
        f"\n[bold green]✅ 分析完成[/] — "
        f"耗時 [yellow]{elapsed:.1f}s[/]，"
        f"共 [yellow]{len(reports)}[/] 個結果\n"
    )

    return reports
