"""
log_parser.py
Parses Apache-combined and SSH auth log lines into a unified pandas DataFrame.
"""

import re
import pandas as pd
from datetime import datetime

# ── Regex patterns ─────────────────────────────────────────────────────────────
APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

SSH_FAILED_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\S+) \S+ sshd\[\d+\]: '
    r'Failed password for (?P<user>\S+) from (?P<ip>\S+)'
)

SSH_SUCCESS_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\S+) \S+ sshd\[\d+\]: '
    r'Accepted password for (?P<user>\S+) from (?P<ip>\S+)'
)

APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S +0000"


def _parse_apache(line: str) -> dict | None:
    m = APACHE_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("timestamp"), APACHE_TS_FMT)
    except ValueError:
        return None
    return {
        "timestamp": ts,
        "source_ip": m.group("ip"),
        "log_type":  "apache",
        "event":     f'{m.group("method")} {m.group("path")}',
        "status":    int(m.group("status")),
        "user":      None,
        "raw":       line.strip(),
    }


def _parse_ssh(line: str) -> dict | None:
    for pattern, success in [(SSH_FAILED_RE, False), (SSH_SUCCESS_RE, True)]:
        m = pattern.search(line)
        if m:
            try:
                # SSH logs lack year; assume current year
                ts_str = f"{m.group('month')} {int(m.group('day')):02d} {m.group('time')} 2024"
                ts = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                ts = datetime.utcnow()
            return {
                "timestamp": ts,
                "source_ip": m.group("ip"),
                "log_type":  "ssh",
                "event":     "ssh_success" if success else "ssh_failed",
                "status":    0 if success else 1,
                "user":      m.group("user"),
                "raw":       line.strip(),
            }
    return None


def parse_log_file(path: str) -> pd.DataFrame:
    """Parse a mixed log file and return a sorted DataFrame."""
    records = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = _parse_apache(line) or _parse_ssh(line)
            if parsed:
                records.append(parsed)

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/sample.log"
    df = parse_log_file(path)
    print(df.head(10).to_string())
    print(f"\nTotal events: {len(df)}")
