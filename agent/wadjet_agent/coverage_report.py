"""Coverage report parsing (section 6): metrics, never findings.

The project's own test step produces ``coverage.xml`` (Cobertura) or
``coverage.json``; the agent turns whatever ``scanners.coverage.report_path``
names into the section 9 metric ``coverage_line_percent`` plus one
``coverage_file_percent:<path>`` metric per file (display data, not gate
metrics). A missing or unreadable report is never a scanner error: the gate
judges it with reason ``"no coverage report"`` (section 6 coverage row), so
parsing only ever warns.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ElementTree

from .adapters import RunContext

#: Key of the overall line-coverage metric (the section 9 gate metric).
OVERALL_KEY = "coverage_line_percent"

#: Prefix of the per-file metrics.
FILE_PREFIX = "coverage_file_percent:"


def configured_report(ctx: RunContext) -> str | None:
    """The configured report path (settings ``scanners.coverage``)."""
    options = ctx.tool_settings("coverage")
    if not ctx.tool_enabled("coverage"):
        return None
    report_path = options.get("report_path")
    if not isinstance(report_path, str) or not report_path.strip():
        return None
    return report_path.strip()


def collect_coverage_metrics(ctx: RunContext) -> tuple[dict[str, float], str | None]:
    """Parse the configured report; returns ``(metrics, warning)``.

    No configuration means no metrics and no warning. A configured-but-broken
    report yields a warning instead of an error, so the analysis stays
    complete and the gate's coverage condition fails with its own reason.
    """
    report_path = configured_report(ctx)
    if report_path is None:
        return {}, None
    report = ctx.repo_root / report_path
    try:
        content = report.read_text(encoding="utf-8")
    except OSError:
        return {}, f"coverage report not found: {report_path}"
    suffix = report.suffix.lower()
    try:
        if suffix == ".json":
            return _from_json(content), None
        if suffix == ".xml":
            return _from_xml(content), None
    except (ValueError, KeyError, TypeError, ElementTree.ParseError):
        return {}, f"coverage report could not be parsed: {report_path}"
    return {}, f"unsupported coverage report format: {report_path} (use .json or .xml)"


def _from_json(content: str) -> dict[str, float]:
    """coverage.py ``coverage json`` output: totals + per-file summaries."""
    data = json.loads(content)
    if not isinstance(data, dict):
        raise TypeError("coverage.json must be an object")
    metrics: dict[str, float] = {}
    totals = data.get("totals")
    if isinstance(totals, dict) and isinstance(totals.get("percent_covered"), (int, float)):
        metrics[OVERALL_KEY] = float(totals["percent_covered"])
    files = data.get("files")
    if isinstance(files, dict):
        for path, entry in files.items():
            summary = entry.get("summary") if isinstance(entry, dict) else None
            percent = summary.get("percent_covered") if isinstance(summary, dict) else None
            if isinstance(percent, (int, float)):
                metrics[FILE_PREFIX + str(path)] = float(percent)
    if OVERALL_KEY not in metrics:
        raise KeyError("coverage.json has no totals.percent_covered")
    return metrics


def _from_xml(content: str) -> dict[str, float]:
    """Cobertura output: exact counts on the root, per-class line elements."""
    root = ElementTree.fromstring(content)
    metrics: dict[str, float] = {}
    covered, valid = _int_attr(root, "lines-covered"), _int_attr(root, "lines-valid")
    if covered is not None and valid:
        metrics[OVERALL_KEY] = covered / valid * 100.0
    else:
        rate = _float_attr(root, "line-rate")
        if rate is None:
            raise KeyError("coverage.xml has no line-rate")
        metrics[OVERALL_KEY] = rate * 100.0

    # Cobertura splits a file into several <class> entries; aggregate the raw
    # line elements per filename so multi-class files stay exact.
    totals: dict[str, list[int]] = {}
    for element in root.iter():
        if _local_name(element.tag) != "class":
            continue
        filename = element.get("filename")
        if not filename:
            continue
        bucket = totals.setdefault(filename, [0, 0])
        for line in element.iter():
            if _local_name(line.tag) != "line":
                continue
            bucket[1] += 1
            if (line.get("hits") or "0") != "0":
                bucket[0] += 1
    for filename, (file_covered, file_valid) in totals.items():
        if file_valid:
            metrics[FILE_PREFIX + filename] = file_covered / file_valid * 100.0
    return metrics


def _local_name(tag: str) -> str:
    """The tag name without an optional XML namespace."""
    return tag.rsplit("}", 1)[-1]


def _int_attr(element: ElementTree.Element, name: str) -> int | None:
    value = element.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_attr(element: ElementTree.Element, name: str) -> float | None:
    value = element.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
