import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, ElasticsearchException

# =========================
# Index names
# =========================
SYSLOG_INDEX = "syslog-*"
METRIC_INDEX = "metricbeat-*"


# =========================
# Elasticsearch client
# =========================
@st.cache_resource(show_spinner=False)
def get_es_client():
    """
    Create a cached Elasticsearch client using secrets.
    """
    ES_HOST = st.secrets["ES_HOST"]
    ES_PORT = int(st.secrets.get("ES_PORT", 9243))
    ES_USER = st.secrets["ES_USER"]
    ES_PASS = st.secrets["ES_PASS"]
    ES_SCHEME = st.secrets.get("ES_SCHEME", "https")

    es = Elasticsearch(
        hosts=[{"host": ES_HOST, "port": ES_PORT, "scheme": ES_SCHEME}],
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=True,
    )
    return es


# =========================
# Helper: time range
# =========================
def sidebar_time_range():
    st.sidebar.header("Time range")
    option = st.sidebar.selectbox(
        "Range",
        ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"],
        index=1,
    )
    now = datetime.now(timezone.utc)
    if option == "Last 15 minutes":
        frm = now - timedelta(minutes=15)
    elif option == "Last 1 hour":
        frm = now - timedelta(hours=1)
    elif option == "Last 6 hours":
        frm = now - timedelta(hours=6)
    else:
        frm = now - timedelta(hours=24)

    # Use ISO8601 for ES range
    return frm.isoformat(), now.isoformat(), option


# =========================
# Helper: safe host info
# =========================
def extract_host_info(src):
    """
    Extract hostname and host_ip from _source with ECS-like mapping.
    """
    host = src.get("host", {}) or {}
    hostname = (
        host.get("hostname")
        or host.get("name")
        or host.get("host")
        or None
    )

    host_ip = host.get("ip")
    if isinstance(host_ip, list) and host_ip:
        host_ip = host_ip[0]

    return hostname, host_ip


def extract_severity(src):
    """
    Extract severity code / label from doc.

    Priority:
      - top-level "severity" / "severity_label"
      - then log.syslog.severity.code / name
    """
    sev_code = src.get("severity")
    sev_label = src.get("severity_label")

    log_obj = src.get("log", {}) or {}
    syslog_obj = log_obj.get("syslog", {}) or {}
    sev_obj = syslog_obj.get("severity", {}) or {}

    if sev_code is None:
        sev_code = sev_obj.get("code")
    if sev_label is None:
        sev_label = sev_obj.get("name")

    return sev_code, sev_label


# =========================
# Dashboard: Overview
# =========================
def render_overview(es, time_from, time_to):
    st.subheader("📊 Overview")

    # 1) Events over time (all severities)
    body_time = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": time_from, "lte": time_to}
            }
        },
        "aggs": {
            "per_interval": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "5m",
                    "min_doc_count": 0,
                }
            }
        },
    }

    res_time = es.search(index=SYSLOG_INDEX, body=body_time)
    buckets = res_time["aggregations"]["per_interval"]["buckets"]
    df_time = pd.DataFrame(
        [
            {
                "timestamp": b["key_as_string"],
                "count": b["doc_count"],
            }
            for b in buckets
        ]
    )

    if df_time.empty:
        st.warning("No syslog events found for this time range.")
        return

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total events", int(df_time["count"].sum()))
    with col2:
        st.metric("Max events / 5 min", int(df_time["count"].max() or 0))

    st.markdown("#### Events over time")
    st.line_chart(df_time.set_index("timestamp"))

    # 2) Severity distribution
    body_sev = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": time_from, "lte": time_to}
            }
        },
        "aggs": {
            "by_sev": {
                "terms": {
                    "field": "severity_label.keyword",  # created by your pipeline
                    "size": 10,
                }
            }
        },
    }
    res_sev = es.search(index=SYSLOG_INDEX, body=body_sev)
    buckets = res_sev["aggregations"]["by_sev"]["buckets"]
    df_sev = pd.DataFrame(
        [{"severity": b["key"], "count": b["doc_count"]} for b in buckets]
    )

    st.markdown("#### Severity distribution")
    if not df_sev.empty:
        st.bar_chart(df_sev.set_index("severity"))
    else:
        st.info("No severity data for this time range.")

    # 3) Top hosts by errors (severity <= 3)
    body_err_host = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {"gte": time_from, "lte": time_to}
                        }
                    },
                    {"range": {"severity": {"lte": 3}}},
                ]
            }
        },
        "aggs": {
            "by_host": {
                "terms": {
                    "field": "host.hostname.keyword",
                    "size": 10,
                }
            }
        },
    }
    res_err_host = es.search(index=SYSLOG_INDEX, body=body_err_host)
    df_host = pd.DataFrame(
        [
            {"host": b["key"], "errors": b["doc_count"]}
            for b in res_err_host["aggregations"]["by_host"]["buckets"]
        ]
    )

    # 4) Top host IP by errors
    body_err_ip = body_err_host.copy()
    body_err_ip["aggs"] = {
        "by_ip": {
            "terms": {
                "field": "host.ip",
                "size": 10,
            }
        }
    }
    res_err_ip = es.search(index=SYSLOG_INDEX, body=body_err_ip)
    df_ip = pd.DataFrame(
        [
            {"ip": b["key"], "errors": b["doc_count"]}
            for b in res_err_ip["aggregations"]["by_ip"]["buckets"]
        ]
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Top hosts by errors (severity ≤ 3)")
        st.dataframe(df_host, use_container_width=True)
    with c2:
        st.markdown("#### Top host IP by errors (severity ≤ 3)")
        st.dataframe(df_ip, use_container_width=True)


# =========================
# Dashboard: Syslog Logs
# =========================
def render_syslog_logs(es, time_from, time_to):
    st.subheader("📜 Syslog Logs")

    severity_options = {
        "All severities": None,
        "Only critical (0–3)": [0, 1, 2, 3],
        "Warning and above (0–4)": [0, 1, 2, 3, 4],
        "Notice and above (0–5)": [0, 1, 2, 3, 4, 5],
    }

    sev_label = st.sidebar.selectbox(
        "Syslog severity filter",
        list(severity_options.keys()),
        index=0,
    )
    sev_codes = severity_options[sev_label]

    msg_filter = st.sidebar.text_input(
        "Search in message (contains, optional)", value=""
    )

    # Query syslog docs
    must_filters = [
        {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}}
    ]
    if sev_codes is not None:
        must_filters.append(
            {"terms": {"severity": sev_codes}}
        )

    if msg_filter:
        must_filters.append(
            {"match_phrase": {"message": msg_filter}}
        )

    body = {
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": must_filters}},
        "_source": [
            "@timestamp",
            "message",
            "host",
            "severity",
            "severity_label",
            "log.syslog.severity",
        ],
    }

    res = es.search(index=SYSLOG_INDEX, body=body)
    hits = res["hits"]["hits"]

    rows = []
    for h in hits:
        src = h["_source"]
        hostname, host_ip = extract_host_info(src)
        sev_code, sev_name = extract_severity(src)
        rows.append(
            {
                "timestamp": src.get("@timestamp"),
                "hostname": hostname,
                "host_ip": host_ip,
                "severity_code": sev_code,
                "severity_name": sev_name,
                "message": src.get("message"),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        st.warning("No syslog events for the selected filters.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total events", len(df))
    with col2:
        err_count = (df["severity_code"] <= 3).sum()
        st.metric("Error events (severity ≤ 3)", int(err_count))
    with col3:
        host_count = df["hostname"].nunique()
        st.metric("Hosts with events", int(host_count))

    # Events over time by severity
    st.markdown("#### Events over time (by severity)")
    df_chart = df.copy()
    df_chart["time_bucket"] = df_chart["timestamp"].dt.floor("1min")
    grp = (
        df_chart.groupby(["time_bucket", "severity_name"])
        .size()
        .reset_index(name="count")
    )
    pivot = grp.pivot(
        index="time_bucket",
        columns="severity_name",
        values="count",
    ).fillna(0)
    st.line_chart(pivot)

    # Host filter + table
    st.markdown("#### Detailed syslog events")
    host_filter = st.multiselect(
        "Filter by hostname",
        options=sorted(df["hostname"].dropna().unique()),
        default=None,
    )

    df_show = df.copy()
    if host_filter:
        df_show = df_show[df_show["hostname"].isin(host_filter)]

    df_show = df_show.sort_values("timestamp", ascending=False)
    df_show = df_show[
        [
            "timestamp",
            "hostname",
            "host_ip",
            "severity_code",
            "severity_name",
            "message",
        ]
    ]
    st.dataframe(df_show, use_container_width=True, height=500)


# =========================
# Dashboard: Metrics
# =========================
def render_metrics(es, time_from, time_to):
    st.subheader("💻 System Health (Metricbeat)")

    # List hosts from metricbeat
    body_hosts = {
        "size": 0,
        "aggs": {
            "hosts": {
                "terms": {
                    "field": "host.name.keyword",
                    "size": 50,
                }
            }
        },
    }
    res_hosts = es.search(index=METRIC_INDEX, body=body_hosts)
    host_buckets = res_hosts["aggregations"]["hosts"]["buckets"]
    hosts = [b["key"] for b in host_buckets]

    if not hosts:
        st.warning("No hosts found in metricbeat-* index.")
        return

    host = st.selectbox("Select host", hosts)

    # CPU / Memory over time
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                    {"term": {"host.name.keyword": host}},
                ]
            }
        },
        "aggs": {
            "per_interval": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "5m",
                    "min_doc_count": 0,
                },
                "aggs": {
                    "cpu": {
                        "avg": {
                            "field": "system.cpu.total.norm.pct"
                        }
                    },
                    "mem": {
                        "avg": {
                            "field": "system.memory.actual.used.pct"
                        }
                    },
                },
            }
        },
    }

    res = es.search(index=METRIC_INDEX, body=body)
    buckets = res["aggregations"]["per_interval"]["buckets"]
    rows = []
    for b in buckets:
        cpu_val = b["cpu"]["value"]
        mem_val = b["mem"]["value"]
        rows.append(
            {
                "timestamp": b["key_as_string"],
                "cpu_pct": cpu_val * 100 if cpu_val is not None else None,
                "mem_pct": mem_val * 100 if mem_val is not None else None,
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No CPU/Memory data for this host in the selected range.")
        return

    avg_cpu = df["cpu_pct"].mean()
    avg_mem = df["mem_pct"].mean()

    c1, c2 = st.columns(2)
    with c1:
        st.metric(
            "Average CPU usage (%)",
            f"{avg_cpu:.1f}" if avg_cpu == avg_cpu else "N/A",
        )
    with c2:
        st.metric(
            "Average Memory usage (%)",
            f"{avg_mem:.1f}" if avg_mem == avg_mem else "N/A",
        )

    st.markdown("#### CPU & Memory usage over time")
    st.line_chart(
        df.set_index("timestamp")[["cpu_pct", "mem_pct"]]
    )

    # Disk usage snapshot
    st.markdown("#### Disk usage (latest max per mount)")

    body_disk = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name.keyword": host}},
                ]
            }
        },
        "aggs": {
            "by_fs": {
                "terms": {
                    "field": "system.filesystem.mount_point.keyword",
                    "size": 20,
                },
                "aggs": {
                    "used": {
                        "max": {
                            "field": "system.filesystem.used.pct"
                        }
                    }
                },
            }
        },
    }

    res_disk = es.search(index=METRIC_INDEX, body=body_disk)
    dbuckets = res_disk["aggregations"]["by_fs"]["buckets"]
    drows = []
    for b in dbuckets:
        used = b["used"]["value"]
        drows.append(
            {
                "mount": b["key"],
                "used_pct": used * 100 if used is not None else None,
            }
        )

    df_disk = pd.DataFrame(drows)
    st.dataframe(df_disk, use_container_width=True)


# =========================
# Dashboard: Security / SSH
# =========================
def render_security_ssh(es, time_from, time_to):
    st.subheader("🛡️ Security / SSH failed logins")

    ssh_query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                {"match_phrase": {"message": "Failed password"}},
            ]
        }
    }

    # Failed logins over time
    body_time = {
        "size": 0,
        "query": ssh_query,
        "aggs": {
            "per_interval": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1h",
                    "min_doc_count": 0,
                }
            }
        },
    }
    res_time = es.search(index=SYSLOG_INDEX, body=body_time)
    buckets = res_time["aggregations"]["per_interval"]["buckets"]
    df_time = pd.DataFrame(
        [
            {
                "timestamp": b["key_as_string"],
                "failed_logins": b["doc_count"],
            }
            for b in buckets
        ]
    )

    st.markdown("#### Failed SSH logins over time")
    if not df_time.empty:
        st.line_chart(df_time.set_index("timestamp"))
    else:
        st.info("No SSH failed login events in this time range.")

    # Top hosts
    body_host = {
        "size": 0,
        "query": ssh_query,
        "aggs": {
            "by_host": {
                "terms": {
                    "field": "host.hostname.keyword",
                    "size": 10,
                }
            }
        },
    }
    res_host = es.search(index=SYSLOG_INDEX, body=body_host)
    df_host = pd.DataFrame(
        [
            {"host": b["key"], "failed_logins": b["doc_count"]}
            for b in res_host["aggregations"]["by_host"]["buckets"]
        ]
    )
    st.markdown("#### Top hosts by SSH failed logins")
    st.dataframe(df_host, use_container_width=True)

    # Raw events
    body_events = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": ssh_query,
        "_source": ["@timestamp", "host", "message"],
    }
    res_ev = es.search(index=SYSLOG_INDEX, body=body_events)
    hits = res_ev["hits"]["hits"]

    rows = []
    for h in hits:
        src = h["_source"]
        hostname, host_ip = extract_host_info(src)
        rows.append(
            {
                "timestamp": src.get("@timestamp"),
                "host": hostname,
                "host_ip": host_ip,
                "message": src.get("message"),
            }
        )
    df_ev = pd.DataFrame(rows)
    st.markdown("#### Latest SSH failed events")
    st.dataframe(df_ev, use_container_width=True, height=400)


# =========================
# Dashboard: Network Devices (VyOS)
# =========================
def render_vyos(es, time_from, time_to):
    st.subheader("🌐 Network Devices (VyOS)")

    keyword = st.sidebar.text_input(
        "Hostname contains (for VyOS)",
        value="vyos",
    )

    sev_option = st.sidebar.selectbox(
        "Severity filter for VyOS",
        ["All severities", "Only errors (≤ 3)", "Warnings and above (≤ 4)"],
        index=0,
    )
    if sev_option == "All severities":
        sev_codes = None
    elif sev_option == "Only errors (≤ 3)":
        sev_codes = [0, 1, 2, 3]
    else:
        sev_codes = [0, 1, 2, 3, 4]

    must_filters = [
        {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
        {"wildcard": {"host.hostname.keyword": f"*{keyword}*"}},
    ]
    if sev_codes is not None:
        must_filters.append({"terms": {"severity": sev_codes}})

    body = {
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": must_filters}},
        "_source": ["@timestamp", "host", "message", "severity", "severity_label"],
    }

    res = es.search(index=SYSLOG_INDEX, body=body)
    hits = res["hits"]["hits"]

    rows = []
    for h in hits:
        src = h["_source"]
        hostname, host_ip = extract_host_info(src)
        sev_code, sev_name = extract_severity(src)
        rows.append(
            {
                "timestamp": src.get("@timestamp"),
                "hostname": hostname,
                "host_ip": host_ip,
                "severity_code": sev_code,
                "severity_name": sev_name,
                "message": src.get("message"),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        st.info(f"No VyOS events for hostnames containing '{keyword}'.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # KPIs
    c1, c2 = st.columns(2)
    with c1:
        st.metric("Total VyOS events", len(df))
    with c2:
        st.metric("Number of VyOS hosts", int(df["hostname"].nunique()))

    # Severity distribution
    st.markdown("#### Severity distribution (VyOS)")
    sev_dist = (
        df.groupby("severity_name").size().reset_index(name="count")
    )
    if not sev_dist.empty:
        st.bar_chart(sev_dist.set_index("severity_name"))
    else:
        st.info("No severity data for VyOS logs.")

    # Events over time
    st.markdown("#### VyOS events over time")
    df_chart = df.copy()
    df_chart["time_bucket"] = df_chart["timestamp"].dt.floor("1min")
    grp = (
        df_chart.groupby(["time_bucket", "severity_name"])
        .size()
        .reset_index(name="count")
    )
    pivot = grp.pivot(
        index="time_bucket",
        columns="severity_name",
        values="count",
    ).fillna(0)
    st.line_chart(pivot)

    # Detail table
    st.markdown("#### Detailed VyOS events")
    df_show = df.sort_values("timestamp", ascending=False)
    df_show = df_show[
        [
            "timestamp",
            "hostname",
            "host_ip",
            "severity_code",
            "severity_name",
            "message",
        ]
    ]
    st.dataframe(df_show, use_container_width=True, height=500)


# =========================
# Main app
# =========================
def main():
    st.set_page_config(
        page_title="Network Log Dashboard",
        layout="wide",
    )
    st.title("Network Monitoring Dashboard")
    st.caption("Streamlit + Elasticsearch (Syslog + Metricbeat + VyOS)")

    try:
        es = get_es_client()
        # Simple health check
        info = es.info()
        cluster_name = info.get("cluster_name", "unknown")
        st.sidebar.success(f"Connected to ES cluster: {cluster_name}")
    except ElasticsearchException as e:
        st.sidebar.error("Failed to connect to Elasticsearch.")
        st.error(f"Elasticsearch error: {e}")
        st.stop()

    time_from, time_to, time_label = sidebar_time_range()
    st.sidebar.markdown(f"**Current time range:** {time_label}")

    section = st.sidebar.radio(
        "Select dashboard",
        [
            "Overview",
            "Syslog Logs",
            "Metrics (CPU/RAM/Disk)",
            "Security / SSH",
            "Network Devices (VyOS)",
        ],
        index=0,
    )

    if section == "Overview":
        render_overview(es, time_from, time_to)
    elif section == "Syslog Logs":
        render_syslog_logs(es, time_from, time_to)
    elif section == "Metrics (CPU/RAM/Disk)":
        render_metrics(es, time_from, time_to)
    elif section == "Security / SSH":
        render_security_ssh(es, time_from, time_to)
    elif section == "Network Devices (VyOS)":
        render_vyos(es, time_from, time_to)


if __name__ == "__main__":
    main()
