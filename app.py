"""
app.py  —  Mini SIEM Dashboard
Run:  streamlit run app.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from src.log_generator   import generate_logs
from src.log_parser      import parse_log_file
from src.anomaly_detector import run_all_detectors, alerts_to_dataframe

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Mini SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', sans-serif;
}
code, .stCode, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Dark terminal palette */
.main { background-color: #0d1117; }
.block-container { padding-top: 1.5rem; }

/* Severity badges */
.badge-CRITICAL { background:#ff4c4c22; color:#ff4c4c; border:1px solid #ff4c4c44;
                  padding:2px 10px; border-radius:4px; font-size:12px; font-weight:600;
                  font-family:'JetBrains Mono',monospace; }
.badge-HIGH     { background:#ff8c0022; color:#ff8c00; border:1px solid #ff8c0044;
                  padding:2px 10px; border-radius:4px; font-size:12px; font-weight:600;
                  font-family:'JetBrains Mono',monospace; }
.badge-MEDIUM   { background:#ffd70022; color:#ffd700; border:1px solid #ffd70044;
                  padding:2px 10px; border-radius:4px; font-size:12px; font-weight:600;
                  font-family:'JetBrains Mono',monospace; }
.badge-LOW      { background:#00bfff22; color:#00bfff; border:1px solid #00bfff44;
                  padding:2px 10px; border-radius:4px; font-size:12px; font-weight:600;
                  font-family:'JetBrains Mono',monospace; }

/* Metric cards */
div[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
}
div[data-testid="metric-container"] label {
    color: #8b949e !important;
    font-size: 12px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
    font-size: 28px !important;
    font-weight: 600 !important;
    color: #e6edf3 !important;
}

/* Alert row colors */
tr.critical-row { background-color: #2d0a0a !important; }
tr.high-row     { background-color: #2d1600 !important; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #21262d;
}
</style>
""", unsafe_allow_html=True)

# ── Helpers ────────────────────────────────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": "#ff4c4c",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#00bfff",
}

PLOT_THEME = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="#0d1117",
    font_color="#8b949e",
    font_family="IBM Plex Sans",
    xaxis=dict(gridcolor="#21262d", linecolor="#30363d"),
    yaxis=dict(gridcolor="#21262d", linecolor="#30363d"),
)


def severity_badge(sev: str) -> str:
    return f'<span class="badge-{sev}">{sev}</span>'


@st.cache_data(ttl=60)
def load_data(log_path: str):
    df     = parse_log_file(log_path)
    alerts = run_all_detectors(df)
    adf    = alerts_to_dataframe(alerts)
    return df, alerts, adf


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Mini SIEM")
    st.markdown("---")

    log_source = st.radio("Log source", ["Generate demo logs", "Upload log file"])

    log_path = "logs/sample.log"
    if log_source == "Generate demo logs":
        days = st.slider("Days of history", 1, 7, 1)
        if st.button("⚡ Generate & Analyze", use_container_width=True):
            with st.spinner("Generating logs…"):
                os.makedirs("logs", exist_ok=True)
                generate_logs(log_path, days=days)
            st.success(f"Generated {days}d of logs")
            st.cache_data.clear()
    else:
        uploaded = st.file_uploader("Upload .log file", type=["log", "txt"])
        if uploaded:
            log_path = "logs/uploaded.log"
            os.makedirs("logs", exist_ok=True)
            with open(log_path, "wb") as f:
                f.write(uploaded.read())
            st.cache_data.clear()

    st.markdown("---")
    st.markdown("**Detectors**")
    st.markdown("✅ SSH Brute Force")
    st.markdown("✅ SQL Injection")
    st.markdown("✅ XSS Attempts")
    st.markdown("✅ Directory/Port Scan")
    st.markdown("✅ Statistical Outlier")
    st.markdown("---")
    st.caption("Mini SIEM · Built with Python + Streamlit")

# ── Load data ──────────────────────────────────────────────────────────────────
if not os.path.exists(log_path):
    st.info("👈 Generate or upload logs using the sidebar to get started.")
    st.stop()

df, alerts, adf = load_data(log_path)

if df.empty:
    st.error("Could not parse any log lines. Check your log format.")
    st.stop()

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Security Event Dashboard")
ts_range = f"{df['timestamp'].min().strftime('%Y-%m-%d %H:%M')}  →  {df['timestamp'].max().strftime('%Y-%m-%d %H:%M')}"
st.caption(f"Log window: {ts_range}  ·  {len(df):,} events parsed")

# ── KPI metrics ───────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
n_critical = len(adf[adf["severity"] == "CRITICAL"]) if not adf.empty else 0
n_high     = len(adf[adf["severity"] == "HIGH"])     if not adf.empty else 0
n_medium   = len(adf[adf["severity"] == "MEDIUM"])   if not adf.empty else 0
unique_ips = df["source_ip"].nunique()
ssh_fails  = len(df[(df["log_type"] == "ssh") & (df["event"] == "ssh_failed")])

c1.metric("🔴 Critical", n_critical)
c2.metric("🟠 High",     n_high)
c3.metric("🟡 Medium",   n_medium)
c4.metric("🌐 Unique IPs", unique_ips)
c5.metric("🔐 SSH Failures", ssh_fails)

st.markdown("---")

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(
    ["📋 Alerts", "📈 Timeline", "🌐 IP Intelligence", "📄 Raw Logs"]
)

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — ALERTS
# ─────────────────────────────────────────────────────────────────────────────
with tab1:
    if adf.empty:
        st.success("✅ No anomalies detected.")
    else:
        # Severity filter
        sev_filter = st.multiselect(
            "Filter by severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )
        filtered = adf[adf["severity"].isin(sev_filter)]

        # Summary donut
        col_a, col_b = st.columns([1, 2])
        with col_a:
            sev_counts = adf["severity"].value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            sev_counts["color"] = sev_counts["severity"].map(SEV_COLORS)
            fig_donut = go.Figure(go.Pie(
                labels=sev_counts["severity"],
                values=sev_counts["count"],
                hole=0.6,
                marker_colors=sev_counts["color"].tolist(),
                textinfo="label+value",
                textfont_size=12,
            ))
            fig_donut.update_layout(
                showlegend=False, height=260, margin=dict(t=20, b=20, l=20, r=20),
                **{k: v for k, v in PLOT_THEME.items() if k != "xaxis" and k != "yaxis"},
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_b:
            rule_bar = adf.groupby(["rule", "severity"]).size().reset_index(name="n")
            fig_bar = px.bar(
                rule_bar, x="rule", y="n", color="severity",
                color_discrete_map=SEV_COLORS,
                labels={"rule": "", "n": "Alerts"},
            )
            fig_bar.update_layout(height=260, margin=dict(t=20, b=60, l=20, r=20),
                                  **PLOT_THEME, legend_title_text="")
            st.plotly_chart(fig_bar, use_container_width=True)

        # Alert table
        st.markdown(f"**{len(filtered)} alert(s)**")
        for _, row in filtered.iterrows():
            with st.expander(
                f"{row['severity']:8} │ {row['rule']:28} │ {row['source_ip']}",
                expanded=(row["severity"] == "CRITICAL"),
            ):
                c1e, c2e, c3e = st.columns(3)
                c1e.markdown(severity_badge(row["severity"]), unsafe_allow_html=True)
                c2e.markdown(f"**Events:** {row['count']}")
                c3e.markdown(f"**Rule:** `{row['rule']}`")
                st.markdown(f"**Description:** {row['description']}")
                st.markdown(
                    f"**Window:** `{row['first_seen'].strftime('%H:%M:%S')}` → "
                    f"`{row['last_seen'].strftime('%H:%M:%S')}`"
                )

                # Find evidence from alert objects
                alert_obj = next(
                    (a for a in alerts
                     if a.source_ip == row["source_ip"] and a.rule == row["rule"]),
                    None,
                )
                if alert_obj and alert_obj.evidence:
                    st.markdown("**Sample log lines:**")
                    for ev in alert_obj.evidence:
                        st.code(ev, language="text")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — TIMELINE
# ─────────────────────────────────────────────────────────────────────────────
with tab2:
    col_t1, col_t2 = st.columns([2, 1])

    with col_t1:
        st.markdown("#### Event volume over time")
        df_time = df.copy()
        df_time["minute"] = df_time["timestamp"].dt.floor("5min")
        vol = df_time.groupby(["minute", "log_type"]).size().reset_index(name="count")
        fig_vol = px.area(
            vol, x="minute", y="count", color="log_type",
            color_discrete_map={"apache": "#00bfff", "ssh": "#ff8c00"},
            labels={"minute": "", "count": "Events", "log_type": "Type"},
        )
        fig_vol.update_layout(height=300, **PLOT_THEME,
                              margin=dict(t=10, b=40, l=40, r=10))
        st.plotly_chart(fig_vol, use_container_width=True)

    with col_t2:
        st.markdown("#### HTTP status codes")
        apache_df = df[df["log_type"] == "apache"]
        if not apache_df.empty:
            status_counts = apache_df["status"].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            status_counts["status"] = status_counts["status"].astype(str)
            color_map = {"200": "#3fb950", "403": "#ff8c00",
                         "404": "#ffd700", "500": "#ff4c4c",
                         "301": "#00bfff", "304": "#8b949e"}
            fig_status = px.pie(
                status_counts, values="count", names="status",
                color="status", color_discrete_map=color_map,
                hole=0.5,
            )
            fig_status.update_layout(
                height=300, showlegend=True,
                margin=dict(t=10, b=10, l=10, r=10),
                **{k: v for k, v in PLOT_THEME.items()
                   if k not in ("xaxis", "yaxis")},
            )
            st.plotly_chart(fig_status, use_container_width=True)

    # SSH failures heatmap
    st.markdown("#### SSH failure heatmap (hour × minute-block)")
    ssh_fail_df = df[(df["log_type"] == "ssh") & (df["event"] == "ssh_failed")].copy()
    if not ssh_fail_df.empty:
        ssh_fail_df["hour"]    = ssh_fail_df["timestamp"].dt.hour
        ssh_fail_df["min_bin"] = (ssh_fail_df["timestamp"].dt.minute // 10) * 10
        heat = ssh_fail_df.groupby(["hour", "min_bin"]).size().reset_index(name="count")
        heat_pivot = heat.pivot(index="hour", columns="min_bin", values="count").fillna(0)
        fig_heat = px.imshow(
            heat_pivot,
            color_continuous_scale=[[0, "#161b22"], [0.5, "#ff8c00"], [1, "#ff4c4c"]],
            labels=dict(x="Minute block", y="Hour", color="Failures"),
            aspect="auto",
        )
        fig_heat.update_layout(height=300, **PLOT_THEME,
                               margin=dict(t=10, b=40, l=60, r=10))
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No SSH failures in this log window.")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 3 — IP INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### Top IPs by event volume")

    ip_stats = df.groupby("source_ip").agg(
        total_events=("timestamp", "count"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        log_types=("log_type", lambda x: ", ".join(sorted(x.unique()))),
        ssh_failures=("event", lambda x: (x == "ssh_failed").sum()),
        http_403s=("status", lambda x: (x == 403).sum()),
    ).reset_index().sort_values("total_events", ascending=False)

    # Tag flagged IPs
    flagged_ips = set(adf["source_ip"].tolist()) if not adf.empty else set()
    ip_stats["flagged"] = ip_stats["source_ip"].apply(
        lambda ip: "⚠️ FLAGGED" if ip in flagged_ips else "✅ Clean"
    )

    col_ip1, col_ip2 = st.columns([3, 2])

    with col_ip1:
        top_n = st.slider("Show top N IPs", 5, 30, 15)
        top_ips = ip_stats.head(top_n)
        colors = ["#ff4c4c" if ip in flagged_ips else "#00bfff"
                  for ip in top_ips["source_ip"]]
        fig_ips = go.Figure(go.Bar(
            x=top_ips["total_events"],
            y=top_ips["source_ip"],
            orientation="h",
            marker_color=colors,
            text=top_ips["total_events"],
            textposition="outside",
        ))
        fig_ips.update_layout(
            height=max(300, top_n * 22),
            **PLOT_THEME,
            margin=dict(t=10, b=20, l=120, r=60),
            yaxis=dict(autorange="reversed", **PLOT_THEME["yaxis"]),
        )
        st.plotly_chart(fig_ips, use_container_width=True)

    with col_ip2:
        st.markdown("**IP detail lookup**")
        selected_ip = st.selectbox("Select IP", ip_stats["source_ip"].tolist())
        row = ip_stats[ip_stats["source_ip"] == selected_ip].iloc[0]
        st.markdown(f"**Status:** {row['flagged']}")
        st.markdown(f"**Total events:** `{row['total_events']}`")
        st.markdown(f"**Log types:** `{row['log_types']}`")
        st.markdown(f"**SSH failures:** `{row['ssh_failures']}`")
        st.markdown(f"**HTTP 403s:** `{row['http_403s']}`")
        st.markdown(f"**First seen:** `{row['first_seen'].strftime('%H:%M:%S')}`")
        st.markdown(f"**Last seen:** `{row['last_seen'].strftime('%H:%M:%S')}`")

        if selected_ip in flagged_ips:
            matching = adf[adf["source_ip"] == selected_ip]
            st.markdown("**Active alerts:**")
            for _, ar in matching.iterrows():
                st.markdown(
                    f"- {severity_badge(ar['severity'])} `{ar['rule']}`",
                    unsafe_allow_html=True,
                )

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4 — RAW LOGS
# ─────────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("#### Raw log viewer")
    col_f1, col_f2, col_f3 = st.columns(3)
    type_filter = col_f1.multiselect("Log type", ["apache", "ssh"],
                                     default=["apache", "ssh"])
    ip_filter   = col_f2.text_input("Filter by IP (partial match)")
    search      = col_f3.text_input("Search in raw line")

    raw_view = df[df["log_type"].isin(type_filter)].copy()
    if ip_filter:
        raw_view = raw_view[raw_view["source_ip"].str.contains(ip_filter, na=False)]
    if search:
        raw_view = raw_view[raw_view["raw"].str.contains(search, case=False, na=False)]

    st.caption(f"Showing {min(500, len(raw_view))} of {len(raw_view)} matching lines")
    for _, row in raw_view.head(500).iterrows():
        highlight = row["source_ip"] in flagged_ips
        prefix    = "🔴 " if highlight else ""
        st.code(f"{prefix}{row['raw']}", language="text")
