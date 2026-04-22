# 🛡️ Mini SIEM Log Analyzer

A Python-based Security Information & Event Management (SIEM) system with anomaly detection and an interactive Streamlit dashboard. Built as a portfolio project covering Security Audit & Compliance + Cybersecurity fundamentals.

---

## Features

| Module | What it does |
|---|---|
| `log_generator.py` | Generates realistic Apache + SSH logs with injected attack patterns |
| `log_parser.py` | Parses raw log lines into a structured pandas DataFrame |
| `anomaly_detector.py` | 5 detectors: SSH brute force, SQLi, XSS, port scan, statistical outlier |
| `app.py` | Streamlit dashboard: alerts, timeline, IP intel, raw log viewer |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the dashboard
streamlit run app.py

# 3. In the sidebar → "Generate demo logs" → click "Generate & Analyze"
```

---

## Project Structure

```
mini-siem/
├── app.py                   # Streamlit dashboard (main entry point)
├── requirements.txt
├── logs/
│   └── sample.log           # Generated or uploaded log file
└── src/
    ├── __init__.py
    ├── log_generator.py     # Demo log generator with attack injection
    ├── log_parser.py        # Apache + SSH log parser → pandas DataFrame
    └── anomaly_detector.py  # Detection engine (5 rule-based detectors)
```

---

## Detection Rules

### 1. SSH Brute Force (`CRITICAL` / `HIGH`)
Flags any IP with ≥ 10 failed SSH logins within a 5-minute rolling window.
- Threshold and window are configurable parameters.
- Severity escalates to CRITICAL above 30 failures.

### 2. SQL Injection (`HIGH`)
Regex-based detection of SQLi indicators in HTTP request paths:
- `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `information_schema`, etc.

### 3. XSS Attempt (`MEDIUM`)
Detects Cross-Site Scripting payloads in request URIs:
- `<script>`, `onerror=`, `javascript:`, `document.cookie`, etc.

### 4. Directory / Port Scan (`HIGH`)
Flags IPs generating ≥ 20 HTTP 404 responses within a 2-minute window — characteristic of automated scanners.

### 5. Statistical Outlier (`MEDIUM`)
Baseline deviation alert: flags any IP whose total event count exceeds mean + 3σ across all sources.

---

## Dashboard Tabs

- **Alerts** — Severity-filtered alert table with evidence log lines, donut chart, and rule breakdown bar chart
- **Timeline** — 5-min event volume area chart, HTTP status pie, SSH failure heatmap
- **IP Intelligence** — Top-N IPs bar chart, per-IP detail panel with active alert links
- **Raw Logs** — Filterable raw log viewer with flagged-IP highlighting

---

## Extending the Project

### Add a new detector
```python
# In src/anomaly_detector.py

def detect_my_rule(df: pd.DataFrame) -> list[Alert]:
    # ... your logic ...
    return [Alert(rule="My Rule", severity=HIGH, ...)]

# Then add it to run_all_detectors():
def run_all_detectors(df):
    return (
        detect_ssh_brute_force(df)
        + detect_sql_injection(df)
        + detect_my_rule(df)   # ← add here
        + ...
    )
```

### Add ML-based detection
Replace or augment `detect_statistical_anomalies()` with an Isolation Forest:
```python
from sklearn.ensemble import IsolationForest

features = df.groupby("source_ip").agg(
    count=("timestamp","count"),
    unique_paths=("event","nunique"),
    error_rate=("status", lambda x: (x >= 400).mean()),
)
clf = IsolationForest(contamination=0.05, random_state=42)
features["anomaly"] = clf.fit_predict(features)
flagged = features[features["anomaly"] == -1]
```

### Real-time log tailing
```python
import time

def tail_log(path, callback):
    with open(path) as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if line:
                callback(line)
            else:
                time.sleep(0.1)
```

### Send Slack alerts
```python
import requests

def slack_alert(webhook_url: str, alert: Alert):
    color = {"CRITICAL":"#ff4c4c","HIGH":"#ff8c00"}.get(alert.severity,"#ffd700")
    requests.post(webhook_url, json={"attachments": [{
        "color": color,
        "title": f"[{alert.severity}] {alert.rule}",
        "text": alert.description,
    }]})
```

---

## Frameworks & Skills Demonstrated

- **Log parsing** — regex, datetime handling, mixed-format ingestion
- **Anomaly detection** — sliding window algorithms, statistical baseline (3-sigma)
- **OWASP Top 10** — SQLi (A03), XSS (A03), Broken Auth (A07) detection
- **NIST SP 800-61** — Incident detection & analysis lifecycle
- **Data visualization** — Plotly, Streamlit, heatmaps, time-series
- **Python packaging** — modular src/ layout, clean separation of concerns

---

## Resume Bullet

> "Built a Python-based mini SIEM system with 5 anomaly detectors (SSH brute force, SQLi, XSS, port scan, statistical outlier) and an interactive Streamlit dashboard for real-time log analysis and incident triage."
