import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import time
import numpy as np
import plotly.express as px

# ========================
# 0) Elasticsearch config
# ========================
ES_HOST = st.secrets["ES_HOST"]
ES_PORT = int(st.secrets.get("ES_PORT", 9243))
ES_USER = st.secrets["ES_USER"]
ES_PASS = st.secrets["ES_PASS"]
ES_SCHEME = st.secrets.get("ES_SCHEME", "https")

SYSLOG_INDEX = "syslog-*"
METRIC_INDEX = "metricbeat-*"

es = Elasticsearch(
    hosts=[{"host": ES_HOST, "port": ES_PORT, "scheme": ES_SCHEME}],
    basic_auth=(ES_USER, ES_PASS),
    verify_certs=True,
)

# ========================
# 1) I18N (EN/VI)
# ========================
LANGS = {
    "en": {
        "page_title": "Network Log Dashboard",
        "title": "Network Monitoring Dashboard",
        "caption": "Built with Streamlit + Elasticsearch",
        "controls": "Controls",
        "select_dashboard": "Select dashboard",
        "dash_syslog": "Syslog Logs",
        "dash_metrics": "Metrics (CPU/RAM/Disk)",
        "dash_vyos": "Network Devices (VyOS)",
        "time_range": "Time range",
        "ranges": ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"],
        "refresh": "Refresh data",
        "sev_filter": "Severity filter",
        "sev_all": "All severities",
        "sev_crit": "Only critical (0–3)",
        "sev_warn": "Warning and above (0–4)",
        "sev_notice": "Notice and above (0–5)",
        "search_msg": "Search in message (optional)",
        "no_syslog_range": "No syslog events found for the selected range.",
        "no_syslog_filter": "No events match the message filter.",
        "total_events": "Total events",
        "error_events": "Error events (severity ≤ 3)",
        "hosts_with_events": "Hosts with events",
        "events_over_time": "Event over time",
        "detailed_syslog": "Detailed syslog events",
        "filter_by_host": "Filter by hostname",
        "metrics_header": "Host Metrics (CPU / Memory / Disk)",
        "no_metric_range": "No metricbeat data found for the selected range.",
        "num_hosts": "Number of hosts",
        "avg_cpu": "Average CPU usage (%)",
        "avg_mem": "Average Memory usage (%)",
        "no_cpu": "No CPU data available.",
        "mem_over_time": "Memory usage over time",
        "no_mem": "No memory data available.",
        "disk_latest": "Disk usage (latest snapshot)",
        "no_disk": "No filesystem usage data available.",
        "vyos_header": "Network Device Logs (VyOS)",
        "vyos_host_contains": "Hostname contains (for VyOS)",
        "vyos_sev_filter": "Severity filter",
        "vyos_sev_all": "All severities",
        "vyos_sev_err": "Only errors (≤ 3)",
        "vyos_sev_warn": "Only warnings and above (≤ 4)",
        "no_syslog_vyos_range": "No syslog events found for the selected range.",
        "no_vyos_host_msg": "No events found for hostnames containing",
        "vyos_total": "Total VyOS events",
        "vyos_hosts": "Number of VyOS hosts",
        "sev_dist": "Severity distribution",
        "vyos_over_time": "VyOS events over time",
        "vyos_detail": "VyOS syslog events",
        "auto_refresh": "Auto refresh",
        "every_secs": "Every (seconds)",
        "sev_chart_type": "Severity chart",
        "pie": "Pie",
        "bar": "Bar",
        "export_csv": "Export CSV",
        "host_details": "Host details",
        "select_host": "Select a host",
        "last_logs": "Last logs",
        "cpu_mem_for_host": "CPU / Memory for selected host",
        "anomaly": "Anomaly (spike) detection",
        "no_data": "No data available.",
        "z_window": "Rolling window (minutes)",
        "z_threshold": "Z-score threshold",
        "spike_table": "Detected spikes",
        "styled_status": "Host status (with thresholds)",
        "cpu_warn": "CPU warn %",
        "mem_warn": "Mem warn %",
        "disk_warn": "Disk warn %",
    },
    "vi": {
        "page_title": "Bảng điều khiển Log Mạng",
        "title": "Bảng điều khiển giám sát mạng",
        "caption": "Xây dựng bằng Streamlit + Elasticsearch",
        "controls": "Điều khiển",
        "select_dashboard": "Chọn bảng điều khiển",
        "dash_syslog": "Nhật ký Syslog",
        "dash_metrics": "Chỉ số (CPU/RAM/Disk)",
        "dash_vyos": "Thiết bị mạng (VyOS)",
        "time_range": "Khoảng thời gian",
        "ranges": ["15 phút gần nhất", "1 giờ gần nhất", "6 giờ gần nhất", "24 giờ gần nhất"],
        "refresh": "Tải lại dữ liệu",
        "sev_filter": "Lọc mức độ nghiêm trọng",
        "sev_all": "Tất cả mức độ",
        "sev_crit": "Chỉ nghiêm trọng (0–3)",
        "sev_warn": "Cảnh báo trở lên (0–4)",
        "sev_notice": "Notice trở lên (0–5)",
        "search_msg": "Tìm trong thông điệp (tùy chọn)",
        "no_syslog_range": "Không có syslog nào trong khoảng thời gian đã chọn.",
        "no_syslog_filter": "Không có sự kiện khớp bộ lọc nội dung.",
        "total_events": "Tổng số sự kiện",
        "error_events": "Sự kiện lỗi (severity ≤ 3)",
        "hosts_with_events": "Số host có sự kiện",
        "events_over_time": "Số lượng sự kiện theo thời gian",
        "detailed_syslog": "Danh sách sự kiện syslog",
        "filter_by_host": "Lọc theo hostname",
        "metrics_header": "Chỉ số máy (CPU / Bộ nhớ / Đĩa)",
        "no_metric_range": "Không có dữ liệu metricbeat trong khoảng thời gian đã chọn.",
        "num_hosts": "Số lượng host",
        "avg_cpu": "CPU trung bình (%)",
        "avg_mem": "Bộ nhớ trung bình (%)",
        "no_cpu": "Không có dữ liệu CPU.",
        "mem_over_time": "Bộ nhớ theo thời gian",
        "no_mem": "Không có dữ liệu bộ nhớ.",
        "disk_latest": "Dung lượng đĩa (snapshot mới nhất)",
        "no_disk": "Không có dữ liệu dung lượng đĩa.",
        "vyos_header": "Nhật ký thiết bị mạng (VyOS)",
        "vyos_host_contains": "Hostname chứa (cho VyOS)",
        "vyos_sev_filter": "Lọc mức độ nghiêm trọng",
        "vyos_sev_all": "Tất cả mức độ",
        "vyos_sev_err": "Chỉ lỗi (≤ 3)",
        "vyos_sev_warn": "Cảnh báo trở lên (≤ 4)",
        "no_syslog_vyos_range": "Không có syslog trong khoảng thời gian đã chọn.",
        "no_vyos_host_msg": "Không có sự kiện cho hostname chứa",
        "vyos_total": "Tổng sự kiện VyOS",
        "vyos_hosts": "Số lượng host VyOS",
        "sev_dist": "Phân bố mức độ nghiêm trọng",
        "vyos_over_time": "Sự kiện VyOS theo thời gian",
        "vyos_detail": "Danh sách syslog của VyOS",
        "auto_refresh": "Tự động tải lại",
        "every_secs": "Mỗi (giây)",
        "sev_chart_type": "Kiểu biểu đồ Severity",
        "pie": "Tròn (Pie)",
        "bar": "Cột (Bar)",
        "export_csv": "Tải CSV",
        "host_details": "Chi tiết theo host",
        "select_host": "Chọn host",
        "last_logs": "Nhật ký gần nhất",
        "cpu_mem_for_host": "CPU / Bộ nhớ của host đã chọn",
        "anomaly": "Phát hiện đột biến (spike)",
        "no_data": "Không có dữ liệu.",
        "z_window": "Cửa sổ cuộn (phút)",
        "z_threshold": "Ngưỡng Z-score",
        "spike_table": "Các spike phát hiện được",
        "styled_status": "Bảng trạng thái (tô màu ngưỡng)",
        "cpu_warn": "Cảnh báo CPU %",
        "mem_warn": "Cảnh báo RAM %",
        "disk_warn": "Cảnh báo Đĩa %",
    },
}

def get_time_range_gte(label: str) -> str:
    # Hỗ trợ cả EN/VI
    if label in ("Last 15 minutes", "15 phút gần nhất"):
        return "now-15m"
    if label in ("Last 1 hour", "1 giờ gần nhất"):
        return "now-1h"
    if label in ("Last 6 hours", "6 giờ gần nhất"):
        return "now-6h"
    if label in ("Last 24 hours", "24 giờ gần nhất"):
        return "now-24h"
    return "now-1h"

# ========================
# 2) Queries
# ========================
def query_syslog(time_range_label: str, severity_codes=None, size: int = 500) -> pd.DataFrame:
    gte = get_time_range_gte(time_range_label)
    must_filters = [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}]
    if severity_codes:
        must_filters.append({"terms": {"log.syslog.severity.code": severity_codes}})

    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "@timestamp",
            "message",
            "host.hostname",
            "host.ip",
            "log.syslog.severity.code",
            "log.syslog.severity.name",
        ],
        "query": {"bool": {"filter": must_filters}},
    }
    res = es.search(index=SYSLOG_INDEX, body=body)
    hits = res.get("hits", {}).get("hits", [])
    rows = []
    for h in hits:
        src = h.get("_source", {})
        host = src.get("host", {}) or {}
        log_sys = src.get("log", {}).get("syslog", {}) or {}
        sev = log_sys.get("severity", {}) or {}
        rows.append(
            {
                "timestamp": src.get("@timestamp"),
                "hostname": host.get("hostname"),
                "host_ip": host.get("ip"),
                "severity_code": sev.get("code"),
                "severity_name": sev.get("name"),
                "message": src.get("message"),
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def query_metrics(time_range_label: str, size: int = 1000) -> pd.DataFrame:
    gte = get_time_range_gte(time_range_label)
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "@timestamp",
            "host.hostname",
            "host.ip",
            "system.cpu.total.norm.pct",
            "system.memory.actual.used.pct",
            "system.filesystem.used.pct",
            "system.filesystem.mount_point",
        ],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}]}},
    }
    res = es.search(index=METRIC_INDEX, body=body)
    hits = res.get("hits", {}).get("hits", [])
    rows = []
    for h in hits:
        src = h.get("_source", {})
        host = src.get("host", {}) or {}
        fs = src.get("system", {}).get("filesystem", {}) or {}
        rows.append(
            {
                "timestamp": src.get("@timestamp"),
                "hostname": host.get("hostname"),
                "host_ip": host.get("ip"),
                "cpu_pct": src.get("system", {}).get("cpu", {}).get("total", {}).get("norm", {}).get("pct"),
                "mem_used_pct": src.get("system", {}).get("memory", {}).get("actual", {}).get("used", {}).get("pct"),
                "fs_used_pct": fs.get("used", {}).get("pct"),
                "fs_mount": fs.get("mount_point"),
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

# ========================
# 3) UI
# ========================
st.set_page_config(page_title=LANGS["en"]["page_title"], layout="wide")

st.sidebar.header(LANGS["en"]["controls"] + " / " + LANGS["vi"]["controls"])
lang_choice = st.sidebar.selectbox("Language / Ngôn ngữ", ["English", "Tiếng Việt"], index=0)
LANG = "en" if lang_choice == "English" else "vi"
T = LANGS[LANG]

st.title(T["title"])
st.caption(T["caption"])

dashboard_type = st.sidebar.radio(
    T["select_dashboard"],
    [T["dash_syslog"], T["dash_metrics"], T["dash_vyos"]],
    index=0,
)

time_range = st.sidebar.selectbox(T["time_range"], T["ranges"], index=1)

st.sidebar.markdown("---")
refresh = st.sidebar.button(T["refresh"])

# ========================
# 4) Syslog dashboard
# ========================
if dashboard_type == T["dash_syslog"]:
    st.subheader(T["dash_syslog"])

    # Severity options per language
    if LANG == "en":
        sev_opts = {
            T["sev_all"]: None,
            T["sev_crit"]: [0, 1, 2, 3],
            T["sev_warn"]: [0, 1, 2, 3, 4],
            T["sev_notice"]: [0, 1, 2, 3, 4, 5],
        }
    else:
        sev_opts = {
            T["sev_all"]: None,
            T["sev_crit"]: [0, 1, 2, 3],
            T["sev_warn"]: [0, 1, 2, 3, 4],
            T["sev_notice"]: [0, 1, 2, 3, 4, 5],
        }

    sev_label = st.sidebar.selectbox(T["sev_filter"], list(sev_opts.keys()), index=0)
    sev_codes = sev_opts[sev_label]

    message_query = st.sidebar.text_input(T["search_msg"], value="")

    df = query_syslog(time_range, sev_codes)
    if df.empty:
        st.warning(T["no_syslog_range"])
    else:
        df = df[df["message"].str.contains(message_query, case=False, na=False)] if message_query else df

    if df.empty:
        st.info(T["no_syslog_filter"])
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(T["total_events"], len(df))
        with col2:
            error_count = (df["severity_code"] <= 3).sum()
            st.metric(T["error_events"], int(error_count))
        with col3:
            host_count = df["hostname"].nunique()
            st.metric(T["hosts_with_events"], int(host_count))

        st.markdown(f"### {T['events_over_time']}")
        df_chart = df.copy()
        df_chart["time_bucket"] = df_chart["timestamp"].dt.floor("1min")
        chart_data = df_chart.groupby(["time_bucket", "severity_name"]).size().reset_index(name="count")
        pivot = chart_data.pivot(index="time_bucket", columns="severity_name", values="count").fillna(0)
        st.line_chart(pivot)

        st.markdown(f"### {T['detailed_syslog']}")
        host_filter = st.multiselect(
            T["filter_by_host"], options=sorted(df["hostname"].dropna().unique()), default=None
        )
        df_show = df.copy()
        if host_filter:
            df_show = df_show[df_show["hostname"].isin(host_filter)]
        df_show = df_show.sort_values("timestamp", ascending=False)[
            ["timestamp", "hostname", "host_ip", "severity_code", "severity_name", "message"]
        ]
        st.dataframe(df_show, use_container_width=True, height=500)
        st.markdown(f"### {T['sev_chart_type']}")
        chart_kind = st.radio("", [T["bar"], T["pie"]], horizontal=True, label_visibility="collapsed")

        sev_dist = (
            df.groupby("severity_name")
              .size().reset_index(name="count")
              .sort_values("count", ascending=False)
        )
        if not sev_dist.empty:
            if chart_kind == T["bar"]:
                st.bar_chart(sev_dist.set_index("severity_name")["count"])
            else:
                fig = px.pie(sev_dist, names="severity_name", values="count", hole=0.25)
                st.plotly_chart(fig, use_container_width=True)

        st.markdown(f"### {T['host_details']}")
        hosts_all = sorted(df["hostname"].dropna().unique())
        sel_host = st.selectbox(T["select_host"], options=hosts_all, index=0 if hosts_all else None)
        
        if sel_host:
            # Last logs for selected host
            st.markdown(f"#### {T['last_logs']}: {sel_host}")
            last_logs = df[df["hostname"] == sel_host].sort_values("timestamp", ascending=False).head(100)
            st.dataframe(last_logs[["timestamp","severity_name","message","host_ip"]], use_container_width=True, height=260)
        
            # CPU/Mem mini chart cho host đã chọn (dùng metricbeat)
            st.markdown(f"#### {T['cpu_mem_for_host']}: {sel_host}")
            dfm_host = query_metrics(time_range)
            dfm_host = dfm_host[dfm_host["hostname"] == sel_host]
            if dfm_host.empty:
                st.info(T["no_data"])
            else:
                cmini1, cmini2 = st.columns(2)
                with cmini1:
                    cpu_df = dfm_host[dfm_host["cpu_pct"].notna()].copy()
                    if not cpu_df.empty:
                        cpu_df["t"] = cpu_df["timestamp"].dt.floor("1min")
                        cpu_line = cpu_df.groupby("t")["cpu_pct"].mean().reset_index()
                        cpu_line = cpu_line.set_index("t") * 100.0
                        st.line_chart(cpu_line)
                    else:
                        st.info("No CPU data.")
                with cmini2:
                    mem_df = dfm_host[dfm_host["mem_used_pct"].notna()].copy()
                    if not mem_df.empty:
                        mem_df["t"] = mem_df["timestamp"].dt.floor("1min")
                        mem_line = mem_df.groupby("t")["mem_used_pct"].mean().reset_index()
                        mem_line = mem_line.set_index("t") * 100.0
                        st.line_chart(mem_line)
                    else:
                        st.info("No memory data.")

# ========================
# 5) Metrics dashboard
# ========================
elif dashboard_type == T["dash_metrics"]:
    st.subheader(T["metrics_header"])
    dfm = query_metrics(time_range)
    if dfm.empty:
        st.warning(T["no_metric_range"])
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            hosts = dfm["hostname"].nunique()
            st.metric(T["num_hosts"], int(hosts))
        with col2:
            avg_cpu = dfm["cpu_pct"].mean() * 100 if dfm["cpu_pct"].notna().any() else None
            st.metric(T["avg_cpu"], f"{avg_cpu:.1f}" if avg_cpu is not None else "N/A")
        with col3:
            avg_mem = dfm["mem_used_pct"].mean() * 100 if dfm["mem_used_pct"].notna().any() else None
            st.metric(T["avg_mem"], f"{avg_mem:.1f}" if avg_mem is not None else "N/A")

        host_filter = st.multiselect(
            T["filter_by_host"], options=sorted(dfm["hostname"].dropna().unique()), default=None
        )
        dfm_show = dfm if not host_filter else dfm[dfm["hostname"].isin(host_filter)]

        if dfm_show.empty:
            st.info(T["no_metric_range"])
        else:
            st.markdown("### CPU")
            cpu_df = dfm_show[dfm_show["cpu_pct"].notna()].copy()
            if not cpu_df.empty:
                cpu_df["time_bucket"] = cpu_df["timestamp"].dt.floor("1min")
                cpu_chart = cpu_df.groupby(["time_bucket", "hostname"])["cpu_pct"].mean().reset_index()
                pivot_cpu = cpu_chart.pivot(index="time_bucket", columns="hostname", values="cpu_pct")
                st.line_chart(pivot_cpu)
            else:
                st.info(T["no_cpu"])

            st.markdown(f"### {T['mem_over_time']}")
            mem_df = dfm_show[dfm_show["mem_used_pct"].notna()].copy()
            if not mem_df.empty:
                mem_df["time_bucket"] = mem_df["timestamp"].dt.floor("1min")
                mem_chart = mem_df.groupby(["time_bucket", "hostname"])["mem_used_pct"].mean().reset_index()
                pivot_mem = mem_chart.pivot(index="time_bucket", columns="hostname", values="mem_used_pct")
                st.line_chart(pivot_mem)
            else:
                st.info(T["no_mem"])

            st.markdown(f"### {T['disk_latest']}")
            disk_df = dfm_show[dfm_show["fs_used_pct"].notna()].copy()
            if not disk_df.empty:
                disk_df = disk_df.sort_values("timestamp").groupby(
                    ["hostname", "fs_mount"], as_index=False
                ).tail(1)
                disk_df["fs_used_pct"] = disk_df["fs_used_pct"] * 100
                disk_df = disk_df[["hostname", "host_ip", "fs_mount", "fs_used_pct"]].sort_values(
                    "fs_used_pct", ascending=False
                )
                st.dataframe(disk_df, use_container_width=True, height=300)
            else:
                st.info(T["no_disk"])

# ========================
# 6) VyOS dashboard
# ========================
elif dashboard_type == T["dash_vyos"]:
    st.subheader(T["vyos_header"])

    keyword = st.sidebar.text_input(T["vyos_host_contains"], value="vyos")
    vyos_sev_choice = st.sidebar.selectbox(
        T["vyos_sev_filter"], [T["vyos_sev_all"], T["vyos_sev_err"], T["vyos_sev_warn"]], index=0
    )
    if vyos_sev_choice == T["vyos_sev_all"]:
        sev_codes_vyos = None
    elif vyos_sev_choice == T["vyos_sev_err"]:
        sev_codes_vyos = [0, 1, 2, 3]
    else:
        sev_codes_vyos = [0, 1, 2, 3, 4]

    df_vyos = query_syslog(time_range, sev_codes_vyos)
    if df_vyos.empty:
        st.warning(T["no_syslog_vyos_range"])
    else:
        df_vyos = df_vyos[df_vyos["hostname"].str.contains(keyword, case=False, na=False)]
        if df_vyos.empty:
            st.info(f"{T['no_vyos_host_msg']} '{keyword}'.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.metric(T["vyos_total"], len(df_vyos))
            with col2:
                st.metric(T["vyos_hosts"], int(df_vyos["hostname"].nunique()))

            st.markdown(f"### {T['sev_dist']}")
            sev_dist = df_vyos.groupby("severity_name").size().reset_index(name="count").sort_values(
                "count", ascending=False
            )
            st.bar_chart(sev_dist.set_index("severity_name")["count"])

            st.markdown(f"### {T['vyos_over_time']}")
            vyos_chart = df_vyos.copy()
            vyos_chart["time_bucket"] = vyos_chart["timestamp"].dt.floor("1min")
            vyos_chart_data = vyos_chart.groupby(["time_bucket", "severity_name"]).size().reset_index(name="count")
            vyos_pivot = vyos_chart_data.pivot(index="time_bucket", columns="severity_name", values="count").fillna(0)
            st.line_chart(vyos_pivot)

            st.markdown(f"### {T['vyos_detail']}")
            df_vyos_show = df_vyos.sort_values("timestamp", ascending=False)[
                ["timestamp", "hostname", "host_ip", "severity_code", "severity_name", "message"]
            ]
            st.dataframe(df_vyos_show, use_container_width=True, height=500)
