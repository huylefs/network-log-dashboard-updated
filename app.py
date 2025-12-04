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

# Khởi tạo kết nối Elasticsearch
es = Elasticsearch(
    hosts=[{"host": ES_HOST, "port": ES_PORT, "scheme": ES_SCHEME}],
    basic_auth=(ES_USER, ES_PASS),
    verify_certs=False,
    ssl_show_warn=False
)

# ========================
# 1) (EN/VI)
# ========================
LANGS = {
    "en": {
        "page_title": "Network Log Dashboard",
        "title": "Network Monitoring Dashboard",
        "caption": "Built with Streamlit + Elasticsearch",
        "controls": "Controls",
        "select_dashboard": "Select dashboard",

        # MENU ITEMS
        "dash_status": "System metrics",
        "dash_security": "Security (SSH)",
        "dash_syslog": "Syslog",
        "dash_vyos": "Network Devices (VyOS)",

        "time_range": "Time range",
        "ranges": ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days"],
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
        "events_over_time": "Events over time",
        "detailed_syslog": "Detailed syslog events",
        "filter_by_host": "Filter by hostname",
        "no_metric_range": "No metricbeat data found for the selected range.",
        "vyos_header": "Network Device Logs (VyOS)",
        "vyos_host_contains": "Hostname contains (for VyOS)",
        "vyos_sev_filter": "Severity filter",
        "vyos_sev_all": "All severities",
        "vyos_sev_err": "Only errors (≤ 3)",
        "vyos_sev_warn": "Warning and above (≤ 4)",
        "no_syslog_vyos_range": "No syslog events found for the selected range.",
        "no_vyos_host_msg": "No events found for hostnames containing",
        "vyos_total": "Total VyOS events",
        "vyos_hosts": "Number of VyOS hosts",
        "vyos_over_time": "VyOS events over time",
        "sev_chart_type": "Severity chart",
        "pie": "Pie",
        "bar": "Bar",

        # STATUS & TRENDS KEYS
        "status_board": "System Health Status",
        "trends_header": "CPU & Memory",
        "select_host_viz": "Select hosts to visualize",
        "cpu_usage": "CPU Usage (%)",
        "mem_usage": "Memory Usage (%)",
        "select_host_trend_info": "Select at least one host to view trends.",

        # SECURITY KEYS
        "sec_failed": "Failed Login Attempts",
        "sec_accepted": "Accepted Logins",
        "sec_users": "Top Hosts (Security Events)",
        "sec_recent_failed": "Recent Failed Logins",
        "sec_no_failed_detected": "No failed login attempts detected.",
        "sec_top_hosts_failures": "Top Hosts with Failures",
        "sec_no_hosts": "No hosts found.",
        "sec_no_failed_data": "No failed login data.",
    },
    "vi": {
        "page_title": "Bảng điều khiển Log Mạng",
        "title": "Bảng điều khiển giám sát mạng",
        "caption": "Xây dựng bằng Streamlit + Elasticsearch",
        "controls": "Điều khiển",
        "select_dashboard": "Chọn bảng điều khiển",

        # MENU ITEMS
        "dash_status": "Thông số hệ thống",
        "dash_security": "Bảo mật (SSH)",
        "dash_syslog": "Nhật ký Syslog",
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
        "no_metric_range": "Không có dữ liệu metricbeat trong khoảng thời gian đã chọn.",
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
        "vyos_over_time": "Sự kiện VyOS theo thời gian",
        "sev_chart_type": "Sự kiện theo mức Severity",
        "pie": "Tròn (Pie)",
        "bar": "Cột (Bar)",

        # STATUS & TRENDS KEYS
        "status_board": "Bảng trạng thái sức khỏe hệ thống",
        "trends_header": "CPU & Bộ nhớ",
        "select_host_viz": "Chọn host để xem biểu đồ",
        "cpu_usage": "Mức sử dụng CPU (%)",
        "mem_usage": "Mức sử dụng bộ nhớ (%)",
        "select_host_trend_info": "Chọn ít nhất một host để xem biểu đồ.",

        # SECURITY KEYS
        "sec_failed": "Đăng nhập thất bại",
        "sec_users": "Các Host đăng nhập thất bại",
        "sec_recent_failed": "Các lần đăng nhập thất bại gần đây",
        "sec_no_failed_detected": "Không phát hiện lần đăng nhập thất bại nào.",
        "sec_top_hosts_failures": "Các host có số lần đăng nhập thất bại nhiều nhất",
        "sec_no_hosts": "Không tìm thấy host nào.",
        "sec_no_failed_data": "Không có dữ liệu đăng nhập thất bại.",
    },
}


def get_time_range_gte(label: str) -> str:
    if label in ("Last 15 minutes", "15 phút gần nhất"):
        return "now-15m"
    if label in ("Last 1 hour", "1 giờ gần nhất"):
        return "now-1h"
    if label in ("Last 6 hours", "6 giờ gần nhất"):
        return "now-6h"
    if label in ("Last 24 hours", "24 giờ gần nhất"):
        return "now-24h"
    if label in ("Last 7 days", "7 ngày gần nhất"):
        return "now-7d"
    return "now-1h"

# ========================
# 2) Queries
# ========================


def query_syslog(time_range_label: str, severity_codes=None, size: int = 2000) -> pd.DataFrame:
    gte = get_time_range_gte(time_range_label)
    must_filters = [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}]
    if severity_codes:
        must_filters.append(
            {"terms": {"log.syslog.severity.code": severity_codes}})

    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "@timestamp", "message", "host.hostname", "host.ip",
            "log.syslog.severity.code", "log.syslog.severity.name"
        ],
        "query": {"bool": {"filter": must_filters}},
    }

    try:
        res = es.search(index=SYSLOG_INDEX, body=body)
        hits = res.get("hits", {}).get("hits", [])
    except Exception as e:
        st.error(f"ES Error (Syslog): {e}")
        return pd.DataFrame()

    rows = []
    for h in hits:
        src = h.get("_source", {})
        host = src.get("host", {}) or {}
        log_sys = src.get("log", {}).get("syslog", {}) or {}
        sev = log_sys.get("severity", {}) or {}
        rows.append({
            "timestamp": src.get("@timestamp"),
            "hostname": host.get("hostname"),
            "host_ip": host.get("ip"),
            "severity_code": sev.get("code"),
            "severity_name": sev.get("name"),
            "message": src.get("message"),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def query_metrics(time_range_label: str, size: int = 2000) -> pd.DataFrame:
    gte = get_time_range_gte(time_range_label)
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "@timestamp", "host.hostname", "host.ip",
            "system.cpu.total.norm.pct",
            "system.memory.actual.used.pct",
            "system.filesystem.used.pct",
            "system.filesystem.mount_point",
        ],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}]}},
    }

    try:
        res = es.search(index=METRIC_INDEX, body=body)
        hits = res.get("hits", {}).get("hits", [])
    except Exception as e:
        st.error(f"ES Error (Metrics): {e}")
        return pd.DataFrame()

    rows = []
    for h in hits:
        src = h.get("_source", {})
        host = src.get("host", {}) or {}
        fs = src.get("system", {}).get("filesystem", {}) or {}
        rows.append({
            "timestamp": src.get("@timestamp"),
            "hostname": host.get("hostname"),
            "host_ip": host.get("ip"),
            "cpu_pct": src.get("system", {}).get("cpu", {}).get("total", {}).get("norm", {}).get("pct"),
            "mem_used_pct": src.get("system", {}).get("memory", {}).get("actual", {}).get("used", {}).get("pct"),
            "fs_used_pct": fs.get("used", {}).get("pct"),
            "fs_mount": fs.get("mount_point"),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


# ========================
# 3) UI Setup
# ========================
st.set_page_config(page_title="Monitor Dashboard", layout="wide")

st.sidebar.header("Controls / Điều khiển")
lang_choice = st.sidebar.selectbox(
    "Language / Ngôn ngữ", ["English", "Tiếng Việt"], index=1)
LANG = "en" if lang_choice == "English" else "vi"
T = LANGS[LANG]

st.title(T["title"])
st.caption(T["caption"])

dashboard_type = st.sidebar.radio(
    T["select_dashboard"],
    [
        T["dash_status"],       
        T["dash_security"],
        T["dash_syslog"],
        T["dash_vyos"]
    ],
    index=0,
)

time_range = st.sidebar.selectbox(T["time_range"], T["ranges"], index=1)
st.sidebar.markdown("---")
if st.sidebar.button(T["refresh"]):
    st.cache_data.clear()

# ========================
# 4) Status Board (Table + Charts)
# ========================
if dashboard_type == T["dash_status"]:
    st.subheader(T["status_board"])

    # Lấy dữ liệu metric (tăng size để vẽ biểu đồ cho đẹp)
    dfm = query_metrics(time_range, size=3000)

    if dfm.empty:
        st.warning(T["no_metric_range"])
    else:

        host_stats = dfm.groupby("hostname").agg({
            "timestamp": "max",             
            "host_ip": "first",
            "cpu_pct": "mean",              
            "mem_used_pct": "mean"          
        }).reset_index()

        # Lấy thông tin Disk Root mới nhất
        df_disk_root = dfm[dfm["fs_mount"] == "/"].copy()

        if not df_disk_root.empty:
            latest_disk = df_disk_root.sort_values(
                "timestamp").groupby("hostname").tail(1)
            latest_disk = latest_disk[["hostname", "fs_used_pct"]]
            latest_disk.columns = ["hostname", "root_disk_usage"]
        else:
            latest_disk = pd.DataFrame(columns=["hostname", "root_disk_usage"])

        # Merge dữ liệu
        final_view = pd.merge(host_stats, latest_disk,
                              on="hostname", how="left")

        # Format dữ liệu hiển thị
        display_df = final_view[[
            "hostname", "host_ip", "timestamp",
            "cpu_pct", "mem_used_pct", "root_disk_usage"
        ]].copy()

        # Chuyển đổi sang %
        display_df["cpu_pct"] = (display_df["cpu_pct"]
                                 * 100).fillna(0).round(1)
        display_df["mem_used_pct"] = (
            display_df["mem_used_pct"] * 100).fillna(0).round(1)
        display_df["root_disk_usage"] = (
            display_df["root_disk_usage"] * 100).fillna(0).round(1)

        display_df.columns = ["Hostname", "IP", "Last Seen",
                              "Avg CPU %", "Avg Mem %", "Root Disk %"]

        # Hàm tô màu
        def style_status(row):
            cpu = row["Avg CPU %"]
            mem = row["Avg Mem %"]
            disk = row["Root Disk %"]

            styles = [''] * len(row)

            if cpu > 75:
                styles[3] = 'background-color: #ffcccc; color: red; font-weight: bold;'
            if mem > 75:
                styles[4] = 'background-color: #ffcccc; color: red; font-weight: bold;'
            if disk > 75:
                styles[5] = 'background-color: #ffcccc; color: red; font-weight: bold;'

            return styles

        st.dataframe(
            display_df.style.apply(style_status, axis=1).format({
                "Last Seen": lambda t: t.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(t) else "N/A"
            }),
            use_container_width=True,
            height=400
        )

        # --- PHẦN 2: BIỂU ĐỒ XU HƯỚNG (CHARTS) ---
        st.divider()
        st.subheader(T["trends_header"])


        all_hosts = sorted(dfm["hostname"].unique())
        selected_hosts = st.multiselect(
            T["select_host_viz"], all_hosts, default=all_hosts)

        if selected_hosts:
            # Lọc data theo host đã chọn
            dfm_chart = dfm[dfm["hostname"].isin(selected_hosts)].copy()

            if not dfm_chart.empty:
 
                dfm_chart["time_bucket"] = dfm_chart["timestamp"].dt.floor(
                    "1min")

                # Biểu đồ CPU
                st.markdown(f"**{T['cpu_usage']}**")
                cpu_data = dfm_chart.pivot_table(
                    index="time_bucket",
                    columns="hostname",
                    values="cpu_pct",
                    aggfunc='mean'
                ) * 100
                st.line_chart(cpu_data)

                # Biểu đồ Memory
                st.markdown(f"**{T['mem_usage']}**")
                mem_data = dfm_chart.pivot_table(
                    index="time_bucket",
                    columns="hostname",
                    values="mem_used_pct",
                    aggfunc='mean'
                ) * 100
                st.line_chart(mem_data)
        else:
            st.info(T["select_host_trend_info"])

# ========================
# 5) Security Dashboard
# ========================
elif dashboard_type == T["dash_security"]:
    st.subheader(T["dash_security"])
    dfs = query_syslog(time_range, size=1000)

    if dfs.empty:
        st.warning(T["no_syslog_range"])
    else:
        # Chỉ lọc log thất bại
        df_fail = dfs[dfs["message"].str.contains(
            "authentication failure", case=False, na=False)]

        # Hiển thị Metric duy nhất
        st.metric(T["sec_failed"], len(df_fail), delta_color="inverse")

        col_main, col_chart = st.columns([2, 1])

        with col_main:
            st.markdown(f"#### {T['sec_recent_failed']}")
            if not df_fail.empty:
                st.dataframe(
                    df_fail[["timestamp", "hostname", "message"]],
                    use_container_width=True,
                    height=400
                )
            else:
                st.success(T["sec_no_failed_detected"])

        with col_chart:
            st.markdown(f"#### {T['sec_users']}")

            # Chỉ sử dụng dữ liệu Failed để vẽ biểu đồ Top Host
            df_interest = df_fail.copy()

            if not df_interest.empty:
                # Đếm hostname bị lỗi nhiều nhất
                host_counts = df_interest["hostname"].value_counts(
                ).reset_index()
                host_counts.columns = ["Hostname", "Count"]

                if not host_counts.empty:
                    fig = px.bar(
                        host_counts.head(10),
                        x="Hostname",
                        y="Count",
                        color="Hostname",
                        title=T["sec_top_hosts_failures"]
                    )
                    fig.update_layout(showlegend=True)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info(T["sec_no_hosts"])
            else:
                st.info(T["sec_no_failed_data"])

# ========================
# 6) Syslog Dashboard
# ========================
elif dashboard_type == T["dash_syslog"]:
    st.subheader(T["dash_syslog"])

    sev_opts = {
        T["sev_all"]: None,
        T["sev_crit"]: [0, 1, 2, 3],
        T["sev_warn"]: [0, 1, 2, 3, 4],
        T["sev_notice"]: [0, 1, 2, 3, 4, 5],
    }
    sev_label = st.sidebar.selectbox(
        T["sev_filter"], list(sev_opts.keys()), index=0)
    sev_codes = sev_opts[sev_label]
    message_query = st.sidebar.text_input(T["search_msg"], value="")

    df = query_syslog(time_range, sev_codes)

    if not df.empty and message_query:
        df = df[df["message"].str.contains(
            message_query, case=False, na=False)]

    if df.empty:
        st.warning(T["no_syslog_range"]
                   if not message_query else T["no_syslog_filter"])
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric(T["total_events"], len(df))
        c2.metric(T["error_events"], int((df["severity_code"] <= 3).sum()))
        c3.metric(T["hosts_with_events"], df["hostname"].nunique())


        col_trend, col_dist = st.columns([2, 1])

def get_syslog_chart_data_agg(time_range_label: str):
    """
    Sử dụng Date Histogram Aggregation để đếm số lượng log theo từng phút.
    Thay thế cho việc tải raw log về rồi dùng pandas groupby.
    """
    gte = get_time_range_gte(time_range_label)
    
    # Cấu trúc Aggregation
    body = {
        "size": 0,  # Quan trọng: Không lấy dữ liệu thô, chỉ lấy kết quả tính toán
        "query": {
            "range": {"@timestamp": {"gte": gte, "lte": "now"}}
        },
        "aggs": {
            # 1. Chia nhỏ thời gian (Bucketing)
            "logs_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1m",  # Gom nhóm mỗi 1 phút
                    "min_doc_count": 0,      # Vẫn hiện các phút không có log (giá trị 0)
                    "extended_bounds": {     # Đảm bảo biểu đồ phủ kín thời gian chọn
                        "min": gte,
                        "max": "now"
                    }
                },
                "aggs": {
                    # 2. Trong mỗi phút, chia theo Severity (Terms Aggregation)
                    "by_severity": {
                        "terms": {"field": "log.syslog.severity.name", "size": 10}
                    }
                }
            }
        }
    }

    res = es.search(index=SYSLOG_INDEX, body=body)
    
    # Phân tích kết quả trả về (Parsing Buckets)
    buckets = res["aggregations"]["logs_over_time"]["buckets"]
    
    data = []
    for bucket in buckets:
        timestamp = bucket["key_as_string"]
        # bucket["by_severity"]["buckets"] chứa danh sách severity trong phút đó
        for sev_bucket in bucket["by_severity"]["buckets"]:
            data.append({
                "time_bucket": timestamp,
                "severity_name": sev_bucket["key"],
                "count": sev_bucket["doc_count"]
            })
            
    # Chuyển thành DataFrame để vẽ biểu đồ
    df = pd.DataFrame(data)
    if not df.empty:
        df["time_bucket"] = pd.to_datetime(df["time_bucket"])
    return df

# ==========================================
# VÍ DỤ 2: Thay thế biểu đồ CPU Trends
# ==========================================
def get_cpu_trends_agg(time_range_label: str, selected_hosts: list = None):
    """
    Tính trung bình CPU theo thời gian cho từng Host sử dụng Aggregation.
    """
    gte = get_time_range_gte(time_range_label)
    
    # Xây dựng bộ lọc host
    filters = [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}]
    if selected_hosts:
        filters.append({"terms": {"host.hostname": selected_hosts}})

    body = {
        "size": 0, # Size = 0 để tối ưu tốc độ
        "query": {"bool": {"filter": filters}},
        "aggs": {
            # 1. Chia theo thời gian
            "cpu_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1m" # Hoặc "5m" nếu khoảng thời gian dài
                },
                "aggs": {
                    # 2. Chia theo Hostname
                    "by_host": {
                        "terms": {"field": "host.hostname", "size": 20}, # Top 20 host
                        "aggs": {
                            # 3. Tính trung bình CPU (Metric Aggregation)
                            "avg_cpu": {
                                "avg": {"field": "system.cpu.total.norm.pct"}
                            }
                        }
                    }
                }
            }
        }
    }

    res = es.search(index=METRIC_INDEX, body=body)
    
    # Parsing
    buckets = res["aggregations"]["cpu_over_time"]["buckets"]
    data = []
    
    for bucket in buckets:
        timestamp = bucket["key_as_string"]
        for host_bucket in bucket["by_host"]["buckets"]:
            avg_val = host_bucket["avg_cpu"]["value"]
            if avg_val is not None:
                data.append({
                    "time_bucket": timestamp,
                    "hostname": host_bucket["key"],
                    "cpu_pct": avg_val
                })

    df = pd.DataFrame(data)
    if not df.empty:
        df["time_bucket"] = pd.to_datetime(df["time_bucket"])
    return df
# ========================
# 7) VyOS Dashboard
# ========================
elif dashboard_type == T["dash_vyos"]:
    st.subheader(T["vyos_header"])

    keyword = st.sidebar.text_input(T["vyos_host_contains"], value="vyos")
    # Thêm ô tìm kiếm nội dung message
    message_query = st.sidebar.text_input(T["search_msg"], value="")

    sev_mode = st.sidebar.selectbox(T["vyos_sev_filter"], [
                                    T["vyos_sev_all"], T["vyos_sev_err"], T["vyos_sev_warn"]])

    sev_codes = None
    if sev_mode == T["vyos_sev_err"]:
        sev_codes = [0, 1, 2, 3]
    if sev_mode == T["vyos_sev_warn"]:
        sev_codes = [0, 1, 2, 3, 4]

    dfv = query_syslog(time_range, sev_codes)
    if not dfv.empty:
        # Lọc theo Hostname
        dfv = dfv[dfv["hostname"].str.contains(keyword, case=False, na=False)]
        # Lọc theo Message (nếu có nhập)
        if message_query:
            dfv = dfv[dfv["message"].str.contains(
                message_query, case=False, na=False)]

    if dfv.empty:
        st.info(f"{T['no_vyos_host_msg']} '{keyword}'" +
                (f" & message '{message_query}'" if message_query else ""))
    else:
        c1, c2 = st.columns(2)
        c1.metric(T["vyos_total"], len(dfv))
        c2.metric(T["vyos_hosts"], dfv["hostname"].nunique())

        # Line Chart (Biểu đồ đường) 
        st.markdown(f"### {T['vyos_over_time']}")
        dfv["time_bucket"] = dfv["timestamp"].dt.floor("1min")
        chart = dfv.groupby(["time_bucket", "severity_name"]
                            ).size().reset_index(name="count")
        st.line_chart(chart.pivot(index="time_bucket",
                      columns="severity_name", values="count").fillna(0))

        # Pie Chart (Biểu đồ tròn) 
        st.markdown(f"### {T['sev_chart_type']}")
        sev_counts = dfv["severity_name"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        # Vẽ biểu đồ tròn
        fig = px.pie(sev_counts, values="Count", names="Severity", hole=0.4)
        st.plotly_chart(fig, use_container_width=True)

        st.dataframe(
            dfv[["timestamp", "hostname", "severity_name", "message"]
                ].sort_values("timestamp", ascending=False),
            use_container_width=True
        )
