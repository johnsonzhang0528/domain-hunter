"""CLI — Command-line interface for Domain Hunter."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

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
    )


# ─────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────
@click.group()
@click.version_option(package_name="domain-hunter")
def main():
    """🔍 Domain Hunter — 全自動過期域名篩選與分析工具

    自動完成 Wayback Machine 歷史分析、反向連結品質檢查、
    安全性檢測、DNS/WHOIS 查詢，並生成綜合評分報告。
    """
    pass


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
