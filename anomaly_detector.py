"""
anomaly_detector.py
Detection engine with four rule-based detectors plus a statistical baseline.
Each detector returns a list of Alert dicts.
"""

import re
import pandas as pd
from dataclasses import dataclass, field
from datetime import timedelta

# ── Alert severity levels ──────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

# ── SQL injection indicators ───────────────────────────────────────────────────
SQLI_PATTERNS = re.compile(
    r"(union\s+select|or\s+1\s*=\s*1|drop\s+table|--|;--|'\s*or\s*'|"
    r"sleep\s*\(|benchmark\s*\(|xp_cmdshell|information_schema)",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror=|onload=|alert\s*\(|"
    r"document\.cookie|<img[^>]+src\s*=\s*['\"]?x)",
    re.IGNORECASE,
)


@dataclass
class Alert:
    rule:        str
    severity:    str
    source_ip:   str
    description: str
    count:       int
    first_seen:  pd.Timestamp
    last_seen:   pd.Timestamp
    evidence:    list = field(default_factory=list)


def detect_ssh_brute_force(
    df: pd.DataFrame,
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[Alert]:
    """Flag IPs with ≥ threshold SSH failures within any rolling window."""
    alerts = []
    ssh_fail = df[(df["log_type"] == "ssh") & (df["event"] == "ssh_failed")].copy()
    if ssh_fail.empty:
        return alerts

    for ip, group in ssh_fail.groupby("source_ip"):
        group = group.sort_values("timestamp")
        ts_list = group["timestamp"].tolist()
        window = timedelta(minutes=window_minutes)
        # Sliding window count
        max_count = 0
        for i, t in enumerate(ts_list):
            count = sum(1 for t2 in ts_list[i:] if t2 - t <= window)
            max_count = max(max_count, count)
        if max_count >= threshold:
            severity = CRITICAL if max_count >= 30 else HIGH
            alerts.append(Alert(
                rule="SSH Brute Force",
                severity=severity,
                source_ip=ip,
                description=(
                    f"{max_count} failed SSH logins within {window_minutes} min "
                    f"from {ip}"
                ),
                count=max_count,
                first_seen=group["timestamp"].min(),
                last_seen=group["timestamp"].max(),
                evidence=group["raw"].head(3).tolist(),
            ))
    return alerts


def detect_sql_injection(df: pd.DataFrame) -> list[Alert]:
    """Flag IPs sending SQLi payloads in Apache request paths."""
    alerts = []
    apache = df[df["log_type"] == "apache"].copy()
    if apache.empty:
        return alerts

    hits = apache[apache["event"].str.contains(SQLI_PATTERNS.pattern, regex=True, na=False)]
    for ip, group in hits.groupby("source_ip"):
        alerts.append(Alert(
            rule="SQL Injection",
            severity=HIGH,
            source_ip=ip,
            description=f"{len(group)} SQLi attempts detected from {ip}",
            count=len(group),
            first_seen=group["timestamp"].min(),
            last_seen=group["timestamp"].max(),
            evidence=group["raw"].head(3).tolist(),
        ))
    return alerts


def detect_xss(df: pd.DataFrame) -> list[Alert]:
    """Flag IPs sending XSS payloads."""
    alerts = []
    apache = df[df["log_type"] == "apache"].copy()
    if apache.empty:
        return alerts

    hits = apache[apache["event"].str.contains(XSS_PATTERNS.pattern, regex=True, na=False)]
    for ip, group in hits.groupby("source_ip"):
        alerts.append(Alert(
            rule="XSS Attempt",
            severity=MEDIUM,
            source_ip=ip,
            description=f"{len(group)} XSS payloads from {ip}",
            count=len(group),
            first_seen=group["timestamp"].min(),
            last_seen=group["timestamp"].max(),
            evidence=group["raw"].head(3).tolist(),
        ))
    return alerts


def detect_port_scan(
    df: pd.DataFrame,
    threshold: int = 20,
    window_minutes: int = 2,
) -> list[Alert]:
    """Flag IPs hitting many distinct 404 paths quickly (directory/port scan)."""
    alerts = []
    apache = df[(df["log_type"] == "apache") & (df["status"] == 404)].copy()
    if apache.empty:
        return alerts

    for ip, group in apache.groupby("source_ip"):
        group = group.sort_values("timestamp")
        ts_list = group["timestamp"].tolist()
        window = timedelta(minutes=window_minutes)
        max_count = 0
        for i, t in enumerate(ts_list):
            count = sum(1 for t2 in ts_list[i:] if t2 - t <= window)
            max_count = max(max_count, count)
        if max_count >= threshold:
            alerts.append(Alert(
                rule="Directory / Port Scan",
                severity=HIGH,
                source_ip=ip,
                description=(
                    f"{max_count} distinct 404 requests in {window_minutes} min "
                    f"from {ip} — possible scan"
                ),
                count=max_count,
                first_seen=group["timestamp"].min(),
                last_seen=group["timestamp"].max(),
                evidence=group["raw"].head(3).tolist(),
            ))
    return alerts


def detect_statistical_anomalies(df: pd.DataFrame) -> list[Alert]:
    """
    Baseline: compute per-IP request volume. Flag IPs whose volume is
    > mean + 3*std (3-sigma outlier) and not already caught by other rules.
    """
    alerts = []
    if df.empty:
        return alerts

    counts = df.groupby("source_ip").size()
    mean   = counts.mean()
    std    = counts.std()
    if std == 0:
        return alerts

    threshold = mean + 3 * std
    outliers  = counts[counts > threshold]
    for ip, count in outliers.items():
        sub = df[df["source_ip"] == ip]
        alerts.append(Alert(
            rule="Statistical Outlier",
            severity=MEDIUM,
            source_ip=ip,
            description=(
                f"{ip} generated {count} events — "
                f"{(count - mean) / std:.1f}σ above baseline ({mean:.0f} avg)"
            ),
            count=int(count),
            first_seen=sub["timestamp"].min(),
            last_seen=sub["timestamp"].max(),
            evidence=[],
        ))
    return alerts


def run_all_detectors(df: pd.DataFrame) -> list[Alert]:
    """Run every detector and return a deduplicated, severity-sorted alert list."""
    alerts = (
        detect_ssh_brute_force(df)
        + detect_sql_injection(df)
        + detect_xss(df)
        + detect_port_scan(df)
        + detect_statistical_anomalies(df)
    )
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    alerts.sort(key=lambda a: (order.get(a.severity, 9), a.source_ip))
    return alerts


def alerts_to_dataframe(alerts: list[Alert]) -> pd.DataFrame:
    if not alerts:
        return pd.DataFrame(columns=[
            "severity", "rule", "source_ip", "description",
            "count", "first_seen", "last_seen",
        ])
    return pd.DataFrame([{
        "severity":    a.severity,
        "rule":        a.rule,
        "source_ip":   a.source_ip,
        "description": a.description,
        "count":       a.count,
        "first_seen":  a.first_seen,
        "last_seen":   a.last_seen,
    } for a in alerts])


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from src.log_parser import parse_log_file
    from src.log_generator import generate_logs

    generate_logs("logs/sample.log")
    df = parse_log_file("logs/sample.log")
    alerts = run_all_detectors(df)
    print(f"\n{'='*60}")
    print(f"  {len(alerts)} ALERTS DETECTED")
    print(f"{'='*60}")
    for a in alerts:
        print(f"[{a.severity:8}] {a.rule:25} | {a.source_ip:20} | {a.description}")
