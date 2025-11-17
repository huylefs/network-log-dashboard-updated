import streamlit as st
import pandas as pd
from datetime import datetime
from elasticsearch import Elasticsearch
import plotly.express as px

# ========================
# 0) Config Elasticsearch
# ========================
# Đọc từ secrets nếu có, nếu không dùng giá trị mặc định
ES_HOST = st.secrets.get("ES_HOST", "192.168.20.50")
ES_PORT = int(st.secrets.get("ES_PORT", 9200))
ES_SCHEME = st.secrets.get("ES_SCHEME", "http")
ES_USER = st.secrets.get("ES_USER", "")
ES_PASS = st.secrets.get("ES_PASS", "")

SYSLOG_INDEX = "syslog-*"
METRIC_INDEX = "metricbeat-*"

if ES_USER and ES_PASS:
    es = Elasticsearch(
        hosts=[{"host": ES_HOST, "port": ES_PORT, "scheme": ES_SCHEME}],
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
    )
else:
    es = Elasticsearch(
        hosts=[{"host": ES_HOST, "port": ES_PORT, "scheme": ES_SCHEME}],
        verify_certs=False,
    )

# ========================
# 1) I18N (EN/VI)
# ========================
LANGS = {
    "en": {
        "title": "Network Monitoring Dashboards",
        "caption": "Streamlit + Elasticsearch (Syslog + Metricbeat)",
        "controls": "Controls",
        "language": "Language",
        "range": "Time range",
        "dashboard": "Select dashboard",
        "overview": "Overview",
        "sys_count": "Logs over time",
        "sev_dist": "Severity distribution",
        "top_err_hosts": "Top hosts by errors (severity ≤ 3)",
        "top_src_ip": "Top source IP",
        "top_hostnames": "Top hostnames",
        "kpi_total": "Total events",
        "kpi_max_5m": "Max events / interval",
        "syslog_not_found": "No syslog events in this time range.",
        "metric": "System Health (Metricbeat)",
        "cpu_mem_disk": "CPU / Memory / Disk over time",
        "host_select": "Filter by hostname",
        "no_metric": "No metricbeat data in this time range.",
        "status_table": "Host status (latest snapshot)",
        "col_ts": "timestamp",
        "col_host": "hostname",
        "col_ip": "host_ip",
        "col_cnt": "count",
        "col_cpu": "CPU (%)",
        "col_mem": "Memory (%)",
        "col_disk": "Disk max (%)",
        "pie": "Pie",
        "bar": "Bar",
        "sev_chart_type": "Severity chart",
        "refresh": "🔄 Refresh",
    },
    "vi": {
        "title": "Bảng điều khiển giám sát mạng",
        "caption": "Streamlit + Elasticsearch (Syslog + Metricbeat)",
        "controls": "Điều khiển",
        "language": "Ngôn ngữ",
        "range": "Khoảng thời gian",
        "dashboard": "Chọn bảng điều khiển",
        "overview": "Tổng quan",
        "sys_count": "Số lượng log theo thời gian",
        "sev_dist": "Phân bố mức độ nghiêm trọng",
        "top_err_hosts": "Top máy theo số lỗi (severity ≤ 3)",
        "top_src_ip": "Top địa chỉ IP nguồn",
        "top_hostnames": "Top hostname",
        "kpi_total": "Tổng số sự kiện",
        "kpi_max_5m": "Số sự kiện tối đa / khoảng",
        "syslog_not_found": "Không có log syslog trong khoảng thời gian này.",
        "metric": "Sức khỏe hệ thống (Metricbeat)",
        "cpu_mem_disk": "CPU / RAM / Disk theo thời gian",
        "host_select": "Lọc theo hostname",
        "no_metric": "Không có dữ liệu metricbeat trong khoảng thời gian này.",
        "status_table": "Bảng trạng thái host (snapshot mới nhất)",
        "col_ts": "thời_gian",
        "col_host": "hostname",
        "col_ip": "host_ip",
        "col_cnt": "số_lượng",
        "col_cpu": "CPU (%)",
        "col_mem": "Bộ nhớ (%)",
        "col_disk": "Đĩa tối đa (%)",
        "pie": "Tròn (Pie)",
        "bar": "Cột (Bar)",
        "sev_chart_type": "Kiểu biểu đồ severity",
        "refresh": "🔄 Tải lại",
    },
}

# ========================
# 2) Helpers
# ========================
def get_time_range_gte(label: str) -> str:
    if label == "Last 15 minutes" or label == "15 phút gần nhất":
        return "now-15m"
    elif label == "Last 1 hour" or label == "1 giờ gần nhất":
        return "now-1h"
    elif label == "Last 6 hours" or label == "6 giờ gần nhất":
        return "now-6h"
    elif label == "Last 24 hours" or label == "24 giờ gần nhất":
        return "now-24h"
    return "now-1h"

@st.cache_data(show_spinner=False, ttl=30)
def es_search(index: str, body: dict) -> dict:
    return es.search(index=index, body=body)

def to_ts_df(buckets, key_field="key_as_string", value_field="doc_count"):
    rows = [{"ts": b.get(key_field), "count": b.get(value_field, 0)} for b in buckets]
    df = pd.DataFrame(rows)
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"])
    return df

def pick_host_ip_value(host_ip):
    if isinstance(host_ip, list) and len(host_ip) > 0:
        return host_ip[0]
    return host_ip

# ========================
# 3) Queries (Overview)
# ========================
@st.cache_data(show_spinner=False, ttl=30)
def q_syslog_ts(gte: str, interval: str = "5m"):
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": gte, "lte": "now"}}},
        "aggs": {
            "per": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                }
            }
        },
    }
    res = es_search(SYSLOG_INDEX, body)
    buckets = res.get("aggregations", {}).get("per", {}).get("buckets", [])
    return to_ts_df(buckets)

@st.cache_data(show_spinner=False, ttl=30)
def q_severity_dist(gte: str, size: int = 10):
    # Thử lấy theo severity_label trước, nếu rỗng thì fallback sang log.syslog.severity.name
    body1 = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": gte, "lte": "now"}}},
        "aggs": {"sev": {"terms": {"field": "severity_label.keyword", "size": size}}},
    }
    res1 = es_search(SYSLOG_INDEX, body1)
    buckets1 = res1.get("aggregations", {}).get("sev", {}).get("buckets", [])

    body2 = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": gte, "lte": "now"}}},
        "aggs": {"sev": {"terms": {"field": "log.syslog.severity.name.keyword", "size": size}}},
    }
    res2 = es_search(SYSLOG_INDEX, body2)
    buckets2 = res2.get("aggregations", {}).get("sev", {}).get("buckets", [])

    buckets = buckets1 if len(buckets1) > 0 else buckets2
    return pd.DataFrame([{"severity": b.get("key"), "count": b.get("doc_count", 0)} for b in buckets])

@st.cache_data(show_spinner=False, ttl=30)
def q_top_error_hosts(gte: str, size: int = 10):
    # Lọc severity ≤ 3 qua nhiều khả năng field
    shoulds = [
        {"range": {"severity": {"lte": 3}}},
        {"range": {"log.syslog.severity.code": {"lte": 3}}},
    ]
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}], "should": shoulds, "minimum_should_match": 1}},
        "aggs": {"by_host": {"terms": {"field": "host.hostname.keyword", "size": size}}},
    }
    res = es_search(SYSLOG_INDEX, body)
    buckets = res.get("aggregations", {}).get("by_host", {}).get("buckets", [])
    return pd.DataFrame([{"hostname": b.get("key"), "count": b.get("doc_count", 0)} for b in buckets])

@st.cache_data(show_spinner=False, ttl=30)
def q_top_source_ip_and_hostname(gte: str, size: int = 10):
    body_ip = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": gte, "lte": "now"}}},
        "aggs": {"by_ip": {"terms": {"field": "host.ip", "size": size}}},
    }
    body_hn = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": gte, "lte": "now"}}},
        "aggs": {"by_hn": {"terms": {"field": "host.hostname.keyword", "size": size}}},
    }
    res_ip = es_search(SYSLOG_INDEX, body_ip)
    res_hn = es_search(SYSLOG_INDEX, body_hn)
    b_ip = res_ip.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    b_hn = res_hn.get("aggregations", {}).get("by_hn", {}).get("buckets", [])
    df_ip = pd.DataFrame([{"host_ip": x.get("key"), "count": x.get("doc_count", 0)} for x in b_ip])
    df_hn = pd.DataFrame([{"hostname": x.get("key"), "count": x.get("doc_count", 0)} for x in b_hn])
    return df_ip, df_hn

# ========================
# 4) Queries (Metricbeat)
# ========================
@st.cache_data(show_spinner=False, ttl=30)
def q_metric_raw(gte: str, size: int = 5000):
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp",
            "host.hostname",
            "host.ip",
            "system.cpu.total.norm.pct",
            "system.memory.actual.used.pct",
            "system.filesystem.used.pct",
            "system.filesystem.mount_point",
        ],
        "query": {"range": {"@timestamp": {"gte": gte, "lte": "now"}}},
    }
    res = es_search(METRIC_INDEX, body)
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
                "host_ip": pick_host_ip_value(host.get("ip")),
                "cpu_pct": (src.get("system", {}).get("cpu", {}).get("total", {}).get("norm", {}).get("pct")),
                "mem_used_pct": (src.get("system", {}).get("memory", {}).get("actual", {}).get("used", {}).get("pct")),
                "fs_used_pct": fs.get("used", {}).get("pct"),
                "fs_mount": fs.get("mount_point"),
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def build_status_table(df: pd.DataFrame) -> pd.DataFrame:
    # Lấy snapshot mới nhất theo host cho CPU/Mem
    last_cpu = (
        df[df["cpu_pct"].notna()]
        .sort_values("timestamp")
        .groupby("hostname", as_index=False)
        .tail(1)[["hostname", "host_ip", "timestamp", "cpu_pct"]]
    )
    last_mem = (
        df[df["mem_used_pct"].notna()]
        .sort_values("timestamp")
        .groupby("hostname", as_index=False)
        .tail(1)[["hostname", "mem_used_pct"]]
    )
    # Với disk: lấy max % used gần nhất trên mỗi host (trong tập đã fetch)
    disk = (
        df[df["fs_used_pct"].notna()][["hostname", "fs_used_pct"]]
        .groupby("hostname", as_index=False)
        .max()
        .rename(columns={"fs_used_pct": "disk_max_pct"})
    )

    # Join
    t = pd.merge(last_cpu, last_mem, on="hostname", how="outer")
    t = pd.merge(t, disk, on="hostname", how="left")

    # Scale %
    if "cpu_pct" in t.columns:
        t["cpu_pct"] = t["cpu_pct"].apply(lambda x: round(x * 100, 1) if pd.notna(x) else x)
    if "mem_used_pct" in t.columns:
        t["mem_used_pct"] = t["mem_used_pct"].apply(lambda x: round(x * 100, 1) if pd.notna(x) else x)
    if "disk_max_pct" in t.columns:
        t["disk_max_pct"] = t["disk_max_pct"].apply(lambda x: round(x * 100, 1) if pd.notna(x) else x)

    return t

# ========================
# 5) UI
# ========================
st.set_page_config(page_title="Network Dashboards", layout="wide")
# Sidebar controls
st.sidebar.header("Controls / Điều khiển")
lang_label = st.sidebar.selectbox("Language / Ngôn ngữ", ["English", "Tiếng Việt"], index=0)
LANG = "en" if lang_label == "English" else "vi"
T = LANGS[LANG]

st.title(T["title"])
st.caption(T["caption"])

time_label = st.sidebar.selectbox(
    T["range"],
    ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"] if LANG=="en"
    else ["15 phút gần nhất", "1 giờ gần nhất", "6 giờ gần nhất", "24 giờ gần nhất"],
    index=1,
)
gte = get_time_range_gte(time_label)
st.sidebar.markdown("---")

dash = st.sidebar.radio(
    T["dashboard"],
    [T["overview"], T["metric"]],
    index=0,
)

refresh = st.sidebar.button(T["refresh"])

# ========================
# 6) DASHBOARD: OVERVIEW
# ========================
if dash == T["overview"]:
    # KPI + Time series
    ts_df = q_syslog_ts(gte, interval="5m")
    if ts_df.empty:
        st.warning(T["syslog_not_found"])
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.metric(T["kpi_total"], int(ts_df["count"].sum()))
        with c2:
            st.metric(T["kpi_max_5m"], int(ts_df["count"].max() or 0))

        st.markdown(f"### {T['sys_count']}")
        st.line_chart(ts_df.set_index("ts")["count"])

    # Severity distribution (bar/pie)
    st.markdown(f"### {T['sev_dist']}")
    chart_type = st.radio(T["sev_chart_type"], [T["bar"], T["pie"]], horizontal=True,
                          index=0 if LANG=="en" else 0)
    sev_df = q_severity_dist(gte)
    if not sev_df.empty:
        if chart_type == T["bar"]:
            st.bar_chart(sev_df.set_index("severity")["count"])
        else:
            fig = px.pie(sev_df, names="severity", values="count", hole=0.25)
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info(T["syslog_not_found"])

    # Top hosts by errors
    st.markdown(f"### {T['top_err_hosts']}")
    top_err = q_top_error_hosts(gte, size=10)
    if not top_err.empty:
        top_err = top_err.rename(columns={"count": T["col_cnt"], "hostname": T["col_host"]})
        st.dataframe(top_err, use_container_width=True, height=300)
    else:
        st.info(T["syslog_not_found"])

    # Top source IP / hostname
    c3, c4 = st.columns(2)
    with c3:
        st.markdown(f"#### {T['top_src_ip']}")
        df_ip, df_hn = q_top_source_ip_and_hostname(gte, size=10)
        if not df_ip.empty:
            st.dataframe(df_ip.rename(columns={"count": T["col_cnt"], "host_ip": T["col_ip"]}),
                         use_container_width=True, height=300)
        else:
            st.info(T["syslog_not_found"])
    with c4:
        st.markdown(f"#### {T['top_hostnames']}")
        if not df_hn.empty:
            st.dataframe(df_hn.rename(columns={"count": T["col_cnt"], "hostname": T["col_host"]}),
                         use_container_width=True, height=300)
        else:
            st.info(T["syslog_not_found"])

# ========================
# 7) DASHBOARD: SYSTEM HEALTH
# ========================
if dash == T["metric"]:
    st.markdown(f"### {T['cpu_mem_disk']}")
    mdf = q_metric_raw(gte)
    if mdf.empty:
        st.warning(T["no_metric"])
    else:
        # Host filter
        hosts = sorted([h for h in mdf["hostname"].dropna().unique()])
        sel_hosts = st.multiselect(T["host_select"], options=hosts, default=hosts[: min(5, len(hosts))])
        show = mdf if len(sel_hosts) == 0 else mdf[mdf["hostname"].isin(sel_hosts)]

        # CPU chart
        cpu_df = show[show["cpu_pct"].notna()].copy()
        if not cpu_df.empty:
            cpu_df["timestamp_floor"] = cpu_df["timestamp"].dt.floor("1min")
            cpu_agg = (
                cpu_df.groupby(["timestamp_floor", "hostname"])["cpu_pct"]
                .mean()
                .reset_index()
            )
            cpu_agg["cpu_pct"] = cpu_agg["cpu_pct"] * 100
            pivot_cpu = cpu_agg.pivot(index="timestamp_floor", columns="hostname", values="cpu_pct")
            st.line_chart(pivot_cpu)
        else:
            st.info("No CPU data.")

        # Memory chart
        mem_df = show[show["mem_used_pct"].notna()].copy()
        if not mem_df.empty:
            mem_df["timestamp_floor"] = mem_df["timestamp"].dt.floor("1min")
            mem_agg = (
                mem_df.groupby(["timestamp_floor", "hostname"])["mem_used_pct"]
                .mean()
                .reset_index()
            )
            mem_agg["mem_used_pct"] = mem_agg["mem_used_pct"] * 100
            pivot_mem = mem_agg.pivot(index="timestamp_floor", columns="hostname", values="mem_used_pct")
            st.line_chart(pivot_mem)
        else:
            st.info("No memory data.")

        # Disk snapshot table (latest per host, max across mounts)
        st.markdown(f"### {T['status_table']}")
        status = build_status_table(show)
        if not status.empty:
            status = status.rename(
                columns={
                    "timestamp": T["col_ts"],
                    "hostname": T["col_host"],
                    "host_ip": T["col_ip"],
                    "cpu_pct": T["col_cpu"],
                    "mem_used_pct": T["col_mem"],
                    "disk_max_pct": T["col_disk"],
                }
            )
            sort_cols = [T["col_cpu"], T["col_mem"], T["col_disk"]]
            existing = [c for c in sort_cols if c in status.columns]
            if existing:
                status = status.sort_values(existing[0], ascending=False)
            st.dataframe(status, use_container_width=True, height=420)
        else:
            st.info("No status rows.")
