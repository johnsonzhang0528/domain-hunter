"""Report generation — HTML, CSV, and console summary."""

from __future__ import annotations

import csv
import datetime as _dt
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.table import Table

from domain_hunter import config as cfg
from domain_hunter.models import DomainReport, Verdict

console = Console()


def print_console_summary(reports: list[DomainReport]) -> None:
    """Print a rich table summary to the console."""
    table = Table(
        title="🔍 Domain Hunter — 分析結果",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
    )

    table.add_column("域名", style="bold")
    table.add_column("總分", justify="center")
    table.add_column("判定", justify="center")
    table.add_column("Wayback", justify="center")
    table.add_column("反連", justify="center")
    table.add_column("安全", justify="center")
    table.add_column("年齡", justify="center")
    table.add_column("垃圾比例", justify="center")
    table.add_column("問題 / 優點", max_width=40)

    for r in reports:
        verdict_style = {
            Verdict.BUY: "[bold green]✅ BUY[/]",
            Verdict.MAYBE: "[bold yellow]⚠️ MAYBE[/]",
            Verdict.REJECT: "[bold red]❌ REJECT[/]",
        }

        score_color = "green" if r.total_score >= 75 else "yellow" if r.total_score >= 50 else "red"

        notes = []
        if r.rejection_reasons:
            notes.extend(r.rejection_reasons[:2])
        if r.positive_signals:
            notes.extend([f"✓ {s}" for s in r.positive_signals[:2]])

        table.add_row(
            r.domain,
            f"[{score_color}]{r.total_score:.0f}[/]",
            verdict_style[r.verdict],
            f"{r.wayback.score:.0f}",
            f"{r.backlinks.score:.0f}",
            f"{r.safety.score:.0f}",
            f"{r.whois.age_years or '?'}y",
            f"{r.backlinks.spam_ratio:.0%}",
            "\n".join(notes) if notes else "—",
        )

    console.print()
    console.print(table)
    console.print()

    # Summary counts
    buy = sum(1 for r in reports if r.verdict == Verdict.BUY)
    maybe = sum(1 for r in reports if r.verdict == Verdict.MAYBE)
    reject = sum(1 for r in reports if r.verdict == Verdict.REJECT)

    console.print(
        f"  [green]BUY: {buy}[/]  "
        f"[yellow]MAYBE: {maybe}[/]  "
        f"[red]REJECT: {reject}[/]  "
        f"Total: {len(reports)}\n"
    )


def generate_html_report(
    reports: list[DomainReport],
    output_path: str | Path | None = None,
) -> Path:
    """Generate a detailed HTML report and return the file path."""
    if output_path is None:
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = cfg.OUTPUT_DIR / f"report_{ts}.html"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(cfg.TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    html = template.render(
        reports=reports,
        generated_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(reports),
        buy_count=sum(1 for r in reports if r.verdict == Verdict.BUY),
        maybe_count=sum(1 for r in reports if r.verdict == Verdict.MAYBE),
        reject_count=sum(1 for r in reports if r.verdict == Verdict.REJECT),
    )

    output_path.write_text(html, encoding="utf-8")
    console.print(f"  📄 HTML 報告已生成: [link=file://{output_path}]{output_path}[/]")
    return output_path


def generate_csv_report(
    reports: list[DomainReport],
    output_path: str | Path | None = None,
) -> Path:
    """Generate a CSV summary report."""
    if output_path is None:
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = cfg.OUTPUT_DIR / f"report_{ts}.csv"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "域名", "總分", "判定",
            "Wayback分數", "反連分數", "安全分數",
            "快照數", "域名年齡", "反連數", "引用域名數",
            "垃圾比例", "PageRank",
            "偵測類別", "垃圾標記",
            "問題", "優點",
        ])

        for r in reports:
            writer.writerow([
                r.domain,
                f"{r.total_score:.1f}",
                r.verdict.value,
                f"{r.wayback.score:.0f}",
                f"{r.backlinks.score:.0f}",
                f"{r.safety.score:.0f}",
                r.wayback.total_snapshots,
                r.whois.age_years or "",
                r.backlinks.total_backlinks,
                r.backlinks.referring_domains,
                f"{r.backlinks.spam_ratio:.2f}",
                f"{r.backlinks.page_rank:.1f}",
                "; ".join(r.wayback.detected_categories),
                "; ".join(r.wayback.spam_flags),
                " | ".join(r.rejection_reasons),
                " | ".join(r.positive_signals),
            ])

    console.print(f"  📊 CSV 報告已生成: [link=file://{output_path}]{output_path}[/]")
    return output_path


def generate_json_report(
    reports: list[DomainReport],
    output_path: str | Path | None = None,
) -> Path:
    """Generate a JSON report with full analysis details."""
    if output_path is None:
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = cfg.OUTPUT_DIR / f"report_{ts}.json"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    import dataclasses

    def to_dict(obj):
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
        if isinstance(obj, list):
            return [to_dict(i) for i in obj]
        if isinstance(obj, dict):
            return {k: to_dict(v) for k, v in obj.items()}
        if isinstance(obj, Verdict):
            return obj.value
        return obj

    data = {
        "generated_at": _dt.datetime.now().isoformat(),
        "total_domains": len(reports),
        "reports": [to_dict(r) for r in reports],
    }

    output_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    console.print(f"  📋 JSON 報告已生成: [link=file://{output_path}]{output_path}[/]")
    return output_path
