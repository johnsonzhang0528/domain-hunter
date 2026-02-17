"""CLI — Command-line interface for Domain Hunter."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from domain_hunter.importers.csv_importer import parse_csv, parse_domain_list
from domain_hunter.pipeline import run_pipeline
from domain_hunter.reports.generator import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    print_console_summary,
)

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
        force=True,
    )


# ─────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────
@click.group()
@click.version_option(package_name="domain-hunter")
def main():
    """🔍 Domain Hunter — 全自動過期域名篩選與分析工具

    自動完成域名搜尋、Wayback Machine 歷史分析、反向連結品質檢查、
    安全性檢測、DNS/WHOIS 查詢，並生成綜合評分報告。

    \b
    一鍵全自動:  domain-hunter hunt outdoor-travel
    指定域名:    domain-hunter check example.com
    CSV 匯入:    domain-hunter analyze domains.csv
    """
    pass


# ═════════════════════════════════════════════
# Command: hunt (全自動一鍵搜尋 + 分析)
# ═════════════════════════════════════════════
@main.command()
@click.argument("profile_name", required=False, default=None)
@click.option(
    "-o", "--output", "output_dir",
    type=click.Path(),
    default=None,
    help="報告輸出目錄 (預設: ./output/)",
)
@click.option(
    "-n", "--max-discover",
    type=int,
    default=None,
    help="最多搜尋域名數量 (預設: 100)",
)
@click.option(
    "-d", "--max-deep",
    type=int,
    default=None,
    help="最多深度分析數量 (預設: 30)",
)
@click.option(
    "-w", "--workers",
    type=int,
    default=None,
    help="並行分析 worker 數量",
)
@click.option("-v", "--verbose", is_flag=True, help="顯示詳細日誌")
def hunt(profile_name, output_dir, max_discover, max_deep, workers, verbose):
    """🎯 一鍵全自動搜尋 — 自動搜尋 → 預篩 → 深度分析 → 只回傳推薦域名

    \b
    PROFILE_NAME: 利基主題 (留空顯示所有可用主題)
      • outdoor-travel  — 戶外露營旅遊
      • taiwan-culture  — 台灣文化廟宇
      • food-recipe     — 美食食譜
      • tech-blog       — 科技部落格
      • general         — 通用 AdSense 友好

    \b
    使用範例:
      domain-hunter hunt outdoor-travel
      domain-hunter hunt taiwan-culture -n 200 -d 50
      domain-hunter hunt general -v
    """
    _setup_logging(verbose)

    from domain_hunter.profiles import get_profile, list_profiles

    # If no profile specified, show available profiles
    if not profile_name:
        _show_profiles()
        return

    # Load profile
    try:
        profile = get_profile(profile_name)
    except KeyError as e:
        console.print(f"[red]❌ {e}[/]")
        _show_profiles()
        sys.exit(1)

    console.print(Panel(
        f"[bold]主題:[/] {profile.name}\n"
        f"[bold]描述:[/] {profile.description}\n"
        f"[bold]搜尋關鍵詞:[/] {', '.join(profile.search_keywords[:8])}...\n"
        f"[bold]偏好 TLD:[/] {', '.join(f'.{t}' for t in profile.preferred_tlds)}",
        title="🎯 Domain Hunter — 一鍵全自動搜尋",
        border_style="green",
    ))

    from domain_hunter import config as cfg
    from domain_hunter.importers.domain_discovery import discover_domains
    from domain_hunter.models import Verdict
    from domain_hunter.prefilter import pre_filter

    max_disc = max_discover or cfg.HUNT_MAX_DISCOVER
    max_dp = max_deep or cfg.HUNT_MAX_DEEP_ANALYZE
    cookie = cfg.EXPIRED_DOMAINS_PHPSESSID

    # ── Step 1: 自動搜尋域名 ─────────────────
    console.print(f"\n[bold cyan]📡 Step 1/4:[/] 搜尋候選域名 (最多 {max_disc} 個)...")

    if cookie:
        console.print("  [green]✓[/] ExpiredDomains.net cookie 已設定")
    else:
        console.print("  [yellow]![/] 未設定 ExpiredDomains cookie — 使用替代搜尋")

    candidates = asyncio.run(discover_domains(
        profile=profile,
        session_cookie=cookie,
        max_total=max_disc,
    ))

    if not candidates:
        console.print("[red]❌ 沒有找到任何候選域名[/]")
        sys.exit(0)

    console.print(f"  [green]✅ 找到 {len(candidates)} 個候選域名[/]")

    # ── Step 2: 快速預篩 ─────────────────────
    console.print(f"\n[bold cyan]🔍 Step 2/4:[/] 快速預篩 (域名名稱 / 年齡 / TLD)...")

    accepted, rejected = pre_filter(candidates, profile)

    console.print(
        f"  [green]✅ 通過預篩: {len(accepted)}[/]  "
        f"[red]❌ 淘汰: {len(rejected)}[/]"
    )

    if verbose and rejected:
        for c, reason in rejected[:10]:
            console.print(f"    [dim]✗ {c.domain}: {reason}[/]")
        if len(rejected) > 10:
            console.print(f"    [dim]... 還有 {len(rejected) - 10} 個被淘汰[/]")

    if not accepted:
        console.print("[red]❌ 所有域名都被預篩淘汰了[/]")
        sys.exit(0)

    # Limit to max_deep for full analysis
    if len(accepted) > max_dp:
        # Prioritize domains with positive keywords in name
        accepted = _sort_by_relevance(accepted, profile)[:max_dp]
        console.print(f"  [yellow]→ 取最相關的 {max_dp} 個進行深度分析[/]")

    # ── Step 3: 深度分析 ─────────────────────
    console.print(f"\n[bold cyan]🔬 Step 3/4:[/] 深度分析 {len(accepted)} 個域名...")
    console.print("  Wayback Machine 歷史 → 反連品質 → 安全檢查 → DNS/WHOIS\n")

    reports = run_pipeline(accepted, max_concurrent=workers)

    # ── Step 4: 只保留推薦域名 ───────────────
    buy_reports = [r for r in reports if r.verdict == Verdict.BUY]
    maybe_reports = [r for r in reports if r.verdict == Verdict.MAYBE]

    console.print(f"\n[bold cyan]🏆 Step 4/4:[/] 篩選結果")
    console.print(
        f"  [green]✅ 推薦購買 (BUY): {len(buy_reports)}[/]  "
        f"[yellow]⚠️ 可考慮 (MAYBE): {len(maybe_reports)}[/]  "
        f"[red]❌ 不適合 (REJECT): {len(reports) - len(buy_reports) - len(maybe_reports)}[/]"
    )

    # Show final results
    final_reports = buy_reports + maybe_reports
    if final_reports:
        print_console_summary(final_reports)
        _generate_reports(reports, output_dir, ("all",))

        # Print purchase action items
        if buy_reports:
            console.print(Panel(
                "\n".join(
                    f"  [green]✅[/] [bold]{r.domain}[/]  "
                    f"(分數: {r.total_score:.0f}, "
                    f"年齡: {r.whois.age_years or '?'}y, "
                    f"垃圾率: {r.backlinks.spam_ratio:.0%})"
                    for r in buy_reports
                ),
                title="🎉 推薦購買清單",
                border_style="green",
            ))
    else:
        console.print("\n[yellow]⚠️ 這次沒有找到完全符合條件的域名[/]")
        console.print("[dim]建議: 調整搜尋參數或換個主題再試一次[/]")
        # Still generate full report for reference
        if reports:
            _generate_reports(reports, output_dir, ("all",))


def _show_profiles() -> None:
    """Display available niche profiles."""
    from domain_hunter.profiles import list_profiles

    table = Table(title="🎯 可用主題 (Niche Profiles)", border_style="blue")
    table.add_column("名稱", style="bold cyan")
    table.add_column("描述")
    table.add_column("用法", style="dim")

    for name, desc in list_profiles():
        table.add_row(name, desc, f"domain-hunter hunt {name}")

    console.print()
    console.print(table)
    console.print()


def _sort_by_relevance(
    candidates: list,
    profile,
) -> list:
    """Sort candidates by relevance to the profile (best first)."""
    import tldextract

    def score(c):
        ext = tldextract.extract(c.domain)
        name = ext.domain.lower()
        s = 0
        # Positive keyword matches
        for kw in profile.domain_positive_keywords:
            if kw in name:
                s += 10
        # Preferred TLD bonus
        if ext.suffix in profile.preferred_tlds[:2]:
            s += 5
        # Shorter names are better
        s -= len(name) * 0.2
        # DP from source data
        if c.dp:
            s += min(c.dp, 50) * 0.1
        return s

    return sorted(candidates, key=score, reverse=True)


# ─────────────────────────────────────────────
# Command: analyze (from CSV)
# ─────────────────────────────────────────────
@main.command()
@click.argument("csv_file", type=click.Path(exists=True))
@click.option(
    "-o", "--output", "output_dir",
    type=click.Path(),
    default=None,
    help="報告輸出目錄 (預設: ./output/)",
)
@click.option(
    "-f", "--format", "formats",
    type=click.Choice(["html", "csv", "json", "all"]),
    multiple=True,
    default=["all"],
    help="輸出格式 (可多選)",
)
@click.option(
    "-w", "--workers",
    type=int,
    default=None,
    help="並行分析的 worker 數量",
)
@click.option("-v", "--verbose", is_flag=True, help="顯示詳細日誌")
def analyze(csv_file, output_dir, formats, workers, verbose):
    """從 ExpiredDomains CSV 匯入域名並執行全自動分析。

    CSV_FILE: ExpiredDomains.net 匯出的 CSV 檔案路徑
    """
    _setup_logging(verbose)

    console.print(f"\n[bold]📂 讀取 CSV:[/] {csv_file}")
    try:
        candidates = parse_csv(csv_file)
    except Exception as exc:
        console.print(f"[red]❌ CSV 解析失敗:[/] {exc}")
        sys.exit(1)

    if not candidates:
        console.print("[yellow]⚠️ CSV 中沒有找到有效域名[/]")
        sys.exit(0)

    console.print(f"[green]✅ 找到 {len(candidates)} 個域名[/]")

    # Run pipeline
    reports = run_pipeline(candidates, max_concurrent=workers)

    # Print console summary
    print_console_summary(reports)

    # Generate reports
    _generate_reports(reports, output_dir, formats)


# ─────────────────────────────────────────────
# Command: check (single/multiple domains)
# ─────────────────────────────────────────────
@main.command()
@click.argument("domains", nargs=-1, required=True)
@click.option(
    "-o", "--output", "output_dir",
    type=click.Path(),
    default=None,
    help="報告輸出目錄",
)
@click.option(
    "-f", "--format", "formats",
    type=click.Choice(["html", "csv", "json", "all"]),
    multiple=True,
    default=["all"],
    help="輸出格式",
)
@click.option("-v", "--verbose", is_flag=True, help="顯示詳細日誌")
def check(domains, output_dir, formats, verbose):
    """直接分析一個或多個域名。

    DOMAINS: 一個或多個域名 (例: example.com another.org)
    """
    _setup_logging(verbose)

    text = "\n".join(domains)
    candidates = parse_domain_list(text)

    if not candidates:
        console.print("[yellow]⚠️ 沒有找到有效域名[/]")
        sys.exit(0)

    console.print(f"[green]✅ 準備分析 {len(candidates)} 個域名[/]")

    reports = run_pipeline(candidates)
    print_console_summary(reports)
    _generate_reports(reports, output_dir, formats)


# ─────────────────────────────────────────────
# Command: batch (from text file, one domain per line)
# ─────────────────────────────────────────────
@main.command()
@click.argument("domain_file", type=click.Path(exists=True))
@click.option(
    "-o", "--output", "output_dir",
    type=click.Path(),
    default=None,
    help="報告輸出目錄",
)
@click.option(
    "-f", "--format", "formats",
    type=click.Choice(["html", "csv", "json", "all"]),
    multiple=True,
    default=["all"],
    help="輸出格式",
)
@click.option(
    "-w", "--workers",
    type=int,
    default=None,
    help="並行 worker 數量",
)
@click.option("-v", "--verbose", is_flag=True, help="顯示詳細日誌")
def batch(domain_file, output_dir, formats, workers, verbose):
    """從純文字檔讀取域名清單（每行一個），執行批次分析。

    DOMAIN_FILE: 域名清單檔案路徑
    """
    _setup_logging(verbose)

    text = Path(domain_file).read_text(encoding="utf-8")
    candidates = parse_domain_list(text)

    if not candidates:
        console.print("[yellow]⚠️ 檔案中沒有找到有效域名[/]")
        sys.exit(0)

    console.print(f"[green]✅ 找到 {len(candidates)} 個域名[/]")

    reports = run_pipeline(candidates, max_concurrent=workers)
    print_console_summary(reports)
    _generate_reports(reports, output_dir, formats)


# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────
def _generate_reports(reports, output_dir, formats):
    """Generate requested report formats."""
    from domain_hunter import config as cfg

    out = Path(output_dir) if output_dir else cfg.OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)

    fmt_set = set(formats)
    do_all = "all" in fmt_set

    console.print("\n[bold]📄 生成報告...[/]")

    if do_all or "html" in fmt_set:
        generate_html_report(reports, out / "report.html")

    if do_all or "csv" in fmt_set:
        generate_csv_report(reports, out / "report.csv")

    if do_all or "json" in fmt_set:
        generate_json_report(reports, out / "report.json")

    console.print(f"\n[bold green]🎉 完成！[/] 報告已儲存至: {out}\n")


if __name__ == "__main__":
    main()
