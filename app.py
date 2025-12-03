import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import time
import numpy as np
import plotly.express as px
import re

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
    verify_certs=False,
    ssl_show_warn=False
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
        # MENU ITEMS
        "dash_syslog": "Syslog Logs",
        "dash_metrics": "Metrics (CPU/RAM/Disk)",
        "dash_vyos": "Network Devices (VyOS)",
        "host_details": "Host Details & Drill-down",
        "dash_security": "Security Audit (SSH/Sudo)",   # NEW
        "dash_status": "Inventory Status Board",        # NEW
        
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
        "sev_chart_type": "Severity chart",
        "pie": "Pie",
        "bar": "Bar",
        "select_host": "Select specific host",
        "last_logs": "Latest Logs for this Host",
        "cpu_mem_for_host": "CPU/Memory History & Anomaly",
        "anomaly": "Anomaly Detection (Z-Score)",
        "spike_table": "Detected Spikes (CPU > 2 StdDev)",
        "no_data_host": "No data found for this host.",
        "current_status": "Current Status",
        # SECURITY & STATUS KEYS
        "sec_failed": "Failed Login Attempts",
        "sec_sudo": "Sudo Usage",
        "sec_accepted": "Accepted Logins",
        "sec_users": "Top Users Targeted",
        "status_board": "System Health Status",
        "status_legend": "Legend: CPU > 90%, Mem > 75%, Disk > 95% -> RED",
    },
    "vi": {
        "page_title": "Bảng điều khiển Log Mạng",
        "title": "Bảng điều khiển giám sát mạng",
        "caption": "Xây dựng bằng Streamlit + Elasticsearch + Anomaly Detection",
        "controls": "Điều khiển",
        "select_dashboard": "Chọn bảng điều khiển",
        # MENU ITEMS
        "dash_syslog": "Nhật ký Syslog",
        "dash_metrics": "Chỉ số (CPU/RAM/Disk)",
        "dash_vyos": "Thiết bị mạng (VyOS)",
        "host_details": "Chi tiết Host & Phân tích",
        "dash_security": "Bảo mật (SSH/Sudo)",          # NEW
        "dash_status": "Trạng thái hệ thống (Status)",  # NEW

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
        "sev_chart_type": "Kiểu biểu đồ Severity",
        "pie": "Tròn (Pie)",
        "bar": "Cột (Bar)",
        "select_host": "Chọn Host cụ thể",
        "last_logs": "Nhật ký mới nhất của Host này",
        "cpu_mem_for_host": "Lịch sử CPU/Bộ nhớ & Bất thường",
        "anomaly": "Phát hiện bất thường (Z-Score)",
        "spike_table": "Các điểm đột biến (CPU > 2 độ lệch chuẩn)",
        "no_data_host": "Không tìm thấy dữ liệu cho host này.",
        "current_status": "Trạng thái hiện tại",
        # SECURITY & STATUS KEYS
        "sec_failed": "Đăng nhập thất bại (Failed)",
        "sec_sudo": "Sử dụng Sudo",
        "sec_accepted": "Đăng nhập thành công",
        "sec_users": "Top User bị tấn công/hoạt động",
        "status_board": "Bảng trạng thái sức khỏe hệ thống",
        "status_legend": "Chú thích: CPU > 90%, RAM > 75%, Disk > 95% -> ĐỎ",
    },
}

def get_time_range_gte(label: str) -> str:
    if label in ("Last 15 minutes", "15 phút gần nhất"): return "now-15m"
    if label in ("Last 1 hour", "1 giờ gần nhất"): return "now-1h"
    if label in ("Last 6 hours", "6 giờ gần nhất"): return "now-6h"
    if label in ("Last 24 hours", "24 giờ gần nhất"): return "now-24h"
    return "now-1h"

# ========================
# 2) Queries
# ========================

def query_syslog(time_range_label: str, severity_codes=None, size: int = 1000) -> pd.DataFrame:
    gte = get_time_range_gte(time_range_label)
    must_filters = [{"range": {"@timestamp": {"gte": gte, "lte": "now"}}}]
    if severity_codes:
        must_filters.append({"terms": {"log.syslog.severity.code": severity_codes}})

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
lang_choice = st.sidebar.selectbox("Language / Ngôn ngữ", ["English", "Tiếng Việt"], index=1)
LANG = "en" if lang_choice == "English" else "vi"
T = LANGS[LANG]

st.title(T["title"])
st.caption(T["caption"])

# Chọn Dashboard
dashboard_type = st.sidebar.radio(
    T["select_dashboard"],
    [
        T["dash_status"],       # NEW: Status Board
        T["dash_security"],     # NEW: Security
        T["host_details"],      # Drill-down
        T["dash_syslog"], 
        T["dash_metrics"], 
        T["dash_vyos"]
    ],
    index=0,
)

time_range = st.sidebar.selectbox(T["time_range"], T["ranges"], index=1)
st.sidebar.markdown("---")
if st.sidebar.button(T["refresh"]):
    st.cache_data.clear()

# ========================
# 4) Status Board (NEW)
# ========================
# ========================
# 4) Status Board (UPDATED: Root Partition Only)
# ========================
if dashboard_type == T["dash_status"]:
    st.subheader(T["status_board"])

    # Lấy dữ liệu metric
    dfm = query_metrics(time_range, size=3000)
    
    if dfm.empty:
        st.warning(T["no_metric_range"])
    else:
        # 1. Lấy thông tin CPU/RAM mới nhất (bất kể mount point là gì)
        # Sắp xếp theo thời gian và lấy dòng cuối cùng của mỗi host
        latest_metrics = dfm.sort_values("timestamp").groupby("hostname").tail(1).copy()
        latest_metrics = latest_metrics[["hostname", "host_ip", "timestamp", "cpu_pct", "mem_used_pct"]]

        # 2. Lấy thông tin Disk chỉ của phân vùng "/" (Root)
        # Lọc bản ghi có mount_point là "/"
        df_disk_root = dfm[dfm["fs_mount"] == "/"].copy()
        
        # Nếu tìm thấy dữ liệu đĩa root
        if not df_disk_root.empty:
            latest_disk = df_disk_root.sort_values("timestamp").groupby("hostname").tail(1)
            latest_disk = latest_disk[["hostname", "fs_used_pct"]]
            latest_disk.columns = ["hostname", "root_disk_usage"] # Đổi tên cột để merge
        else:
            # Trường hợp không có dữ liệu mount point "/" (ví dụ Windows hoặc path lạ)
            latest_disk = pd.DataFrame(columns=["hostname", "root_disk_usage"])

        # 3. Merge CPU/RAM với Disk theo Hostname
        final_view = pd.merge(latest_metrics, latest_disk, on="hostname", how="left")
        
        # 4. Làm đẹp dữ liệu hiển thị
        display_df = final_view[[
            "hostname", "host_ip", "timestamp", 
            "cpu_pct", "mem_used_pct", "root_disk_usage"
        ]].copy()

        # Chuyển đổi sang % và xử lý NaN (nếu host chưa gửi log đĩa)
        display_df["cpu_pct"] = (display_df["cpu_pct"] * 100).fillna(0).round(1)
        display_df["mem_used_pct"] = (display_df["mem_used_pct"] * 100).fillna(0).round(1)
        display_df["root_disk_usage"] = (display_df["root_disk_usage"] * 100).fillna(0).round(1)

        display_df.columns = ["Hostname", "IP", "Last Seen", "CPU %", "Mem %", "Root Disk %"]

        # 5. Hàm tô màu (Updated Logic)
        def style_status(row):
            cpu = row["CPU %"]
            mem = row["Mem %"]
            disk = row["Root Disk %"]
            
            styles = [''] * len(row)
            
            # Tô màu CPU
            if cpu > 90: 
                styles[3] = 'background-color: #ffcccc; color: red; font-weight: bold;'
            
            # Tô màu RAM
            if mem > 75: 
                styles[4] = 'background-color: #ffcccc; color: red; font-weight: bold;'
            
            # Tô màu Disk (Chỉ tính Root Partition)
            if disk > 95: 
                styles[5] = 'background-color: #ffcccc; color: red; font-weight: bold;'
            
            return styles

        st.dataframe(
            display_df.style.apply(style_status, axis=1).format({
                "Last Seen": lambda t: t.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(t) else "N/A"
            }),
            use_container_width=True,
            height=600
        )

# ========================
# 5) Security Dashboard (NEW)
# ========================
elif dashboard_type == T["dash_security"]:
    st.subheader(T["dash_security"])
    dfs = query_syslog(time_range, size=1000)
    
    if dfs.empty:
        st.warning(T["no_syslog_range"])
    else:
        # Lọc các log liên quan đến bảo mật
        # authentication failure: log thất bại
        # Accepted: log thành công (thường là SSH)
        # sudo: log lệnh sudo
        
        # Regex đơn giản hóa filter để bắt được nhiều trường hợp hơn
        df_fail = dfs[dfs["message"].str.contains("failure|Failed", case=False, na=False)]
        df_success = dfs[dfs["message"].str.contains("Accepted|session opened", case=False, na=False)]
        df_sudo = dfs[dfs["message"].str.contains("sudo", case=False, na=False)]

        c1, c2, c3 = st.columns(3)
        c1.metric(T["sec_failed"], len(df_fail), delta_color="inverse")
        c2.metric(T["sec_accepted"], len(df_success))
        c3.metric(T["sec_sudo"], len(df_sudo))

        col_main, col_users = st.columns([2, 1])

        with col_main:
            st.markdown("#### Recent Failed Logins")
            if not df_fail.empty:
                st.dataframe(df_fail[["timestamp", "hostname", "message"]], use_container_width=True, height=300)
            else:
                st.success("No failed login attempts detected.")

        with col_users:
            st.markdown(f"#### {T['sec_users']}")
            
            # --- HÀM EXTRACT ĐÃ ĐƯỢC CHỈNH SỬA ĐƠN GIẢN HÓA ---
            def extract_user(msg):
                if not isinstance(msg, str): return "unknown"
                
                # 1. Ưu tiên format Key-Value như mẫu bạn gửi (user=huyle203)
                # \buser= : Tìm chữ "user=" đứng độc lập (tránh nhầm với ruser=)
                # (\S+)   : Lấy chuỗi ký tự liền sau (không chứa khoảng trắng)
                match_kv = re.search(r"\buser=(\S+)", msg)
                if match_kv:
                    return match_kv.group(1)

                # 2. Fallback: Nếu log không có user=..., thử tìm ruser= (remote user)
                match_ruser = re.search(r"\bruser=(\S+)", msg)
                if match_ruser:
                    return match_ruser.group(1)

                # 3. Fallback cuối: Cho log SSH cũ kiểu text (Accepted for root...)
                match_ssh = re.search(r"for\s+(?:invalid user\s+)?(\S+)", msg)
                if match_ssh and "from" in msg: # Chỉ lấy nếu câu có chữ "from" để chắc chắn
                    return match_ssh.group(1)
                    
                return "unknown"
            # --------------------------------------------------

            df_interest = pd.concat([df_fail, df_success, df_sudo]) # Gộp cả sudo để xem ai hay gõ lệnh
            if not df_interest.empty:
                df_interest["extracted_user"] = df_interest["message"].apply(extract_user)
                
                # Loại bỏ unknown và rỗng
                user_counts = df_interest[
                    (df_interest["extracted_user"] != "unknown") & 
                    (df_interest["extracted_user"] != "")
                ]["extracted_user"].value_counts().reset_index()
                
                user_counts.columns = ["User", "Count"]
                
                if not user_counts.empty:
                    fig = px.bar(user_counts.head(10), x="Count", y="User", orientation='h')
                    fig.update_layout(yaxis=dict(autorange="reversed"))
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No usernames extracted.")
            else:
                st.info("No data.")
# ========================
# 6) Syslog Dashboard (Old)
# ========================
elif dashboard_type == T["dash_syslog"]:
    st.subheader(T["dash_syslog"])
    
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
    
    if not df.empty and message_query:
        df = df[df["message"].str.contains(message_query, case=False, na=False)]

    if df.empty:
        st.warning(T["no_syslog_range"] if not message_query else T["no_syslog_filter"])
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric(T["total_events"], len(df))
        c2.metric(T["error_events"], int((df["severity_code"] <= 3).sum()))
        c3.metric(T["hosts_with_events"], df["hostname"].nunique())

        st.markdown(f"### {T['events_over_time']}")
        df_chart = df.copy()
        df_chart["time_bucket"] = df_chart["timestamp"].dt.floor("1min")
        chart_data = df_chart.groupby(["time_bucket", "severity_name"]).size().reset_index(name="count")
        st.line_chart(chart_data.pivot(index="time_bucket", columns="severity_name", values="count").fillna(0))

        st.markdown(f"### {T['detailed_syslog']}")
        host_filter = st.multiselect(T["filter_by_host"], options=sorted(df["hostname"].dropna().unique()))
        if host_filter:
            df = df[df["hostname"].isin(host_filter)]
        
        st.dataframe(
            df[["timestamp", "hostname", "severity_name", "message"]].sort_values("timestamp", ascending=False),
            use_container_width=True, height=400
        )

# ========================
# 7) Metrics Dashboard (Old)
# ========================
elif dashboard_type == T["dash_metrics"]:
    st.subheader(T["metrics_header"])
    dfm = query_metrics(time_range)

    if dfm.empty:
        st.warning(T["no_metric_range"])
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric(T["num_hosts"], dfm["hostname"].nunique())
        
        avg_cpu = dfm["cpu_pct"].mean() * 100 if dfm["cpu_pct"].notna().any() else 0
        c2.metric(T["avg_cpu"], f"{avg_cpu:.1f}")
        
        avg_mem = dfm["mem_used_pct"].mean() * 100 if dfm["mem_used_pct"].notna().any() else 0
        c3.metric(T["avg_mem"], f"{avg_mem:.1f}")

        host_filter = st.multiselect(T["filter_by_host"], options=sorted(dfm["hostname"].dropna().unique()))
        if host_filter:
            dfm = dfm[dfm["hostname"].isin(host_filter)]

        st.markdown("### CPU (%)")
        if not dfm.empty:
            dfm["time_bucket"] = dfm["timestamp"].dt.floor("1min")
            
            cpu_pivot = dfm.groupby(["time_bucket", "hostname"])["cpu_pct"].mean().reset_index()
            st.line_chart(cpu_pivot.pivot(index="time_bucket", columns="hostname", values="cpu_pct"))

            st.markdown(f"### {T['mem_over_time']}")
            mem_pivot = dfm.groupby(["time_bucket", "hostname"])["mem_used_pct"].mean().reset_index()
            st.line_chart(mem_pivot.pivot(index="time_bucket", columns="hostname", values="mem_used_pct"))

            st.markdown(f"### {T['disk_latest']}")
            disk_df = dfm[dfm["fs_used_pct"].notna()].sort_values("timestamp")
            disk_latest = disk_df.groupby(["hostname", "fs_mount"]).tail(1).copy()
            disk_latest["fs_used_pct"] = (disk_latest["fs_used_pct"] * 100).round(1)
            
            st.dataframe(
                disk_latest[["hostname", "fs_mount", "fs_used_pct"]].sort_values("fs_used_pct", ascending=False),
                use_container_width=True
            )

# ========================
# 8) VyOS Dashboard (Old)
# ========================
elif dashboard_type == T["dash_vyos"]:
    st.subheader(T["vyos_header"])
    
    keyword = st.sidebar.text_input(T["vyos_host_contains"], value="vyos")
    sev_mode = st.sidebar.selectbox(T["vyos_sev_filter"], [T["vyos_sev_all"], T["vyos_sev_err"], T["vyos_sev_warn"]])
    
    sev_codes = None
    if sev_mode == T["vyos_sev_err"]: sev_codes = [0, 1, 2, 3]
    if sev_mode == T["vyos_sev_warn"]: sev_codes = [0, 1, 2, 3, 4]

    dfv = query_syslog(time_range, sev_codes)
    if not dfv.empty:
        dfv = dfv[dfv["hostname"].str.contains(keyword, case=False, na=False)]

    if dfv.empty:
        st.info(f"{T['no_vyos_host_msg']} '{keyword}'")
    else:
        c1, c2 = st.columns(2)
        c1.metric(T["vyos_total"], len(dfv))
        c2.metric(T["vyos_hosts"], dfv["hostname"].nunique())

        st.markdown(f"### {T['vyos_over_time']}")
        dfv["time_bucket"] = dfv["timestamp"].dt.floor("1min")
        chart = dfv.groupby(["time_bucket", "severity_name"]).size().reset_index(name="count")
        st.line_chart(chart.pivot(index="time_bucket", columns="severity_name", values="count").fillna(0))

        st.dataframe(
            dfv[["timestamp", "hostname", "severity_name", "message"]].sort_values("timestamp", ascending=False),
            use_container_width=True
        )

# ========================
# 9) Host Details & Anomaly
# ========================
elif dashboard_type == T["host_details"]:
    st.subheader(T["host_details"])

    aggs_body = {
        "size": 0,
        "aggs": {
            "unique_hosts": {"terms": {"field": "host.hostname", "size": 100}}
        },
        "query": {"range": {"@timestamp": {"gte": get_time_range_gte(time_range)}}}
    }
    
    host_list = []
    try:
        res_hosts = es.search(index=METRIC_INDEX, body=aggs_body)
        buckets = res_hosts.get("aggregations", {}).get("unique_hosts", {}).get("buckets", [])
        host_list = [b["key"] for b in buckets]
    except Exception:
        pass

    if not host_list:
        st.warning(T["no_metric_range"])
    else:
        selected_host = st.selectbox(T["select_host"], sorted(host_list))
        
        dfm_host = query_metrics(time_range, size=2000)
        dfm_host = dfm_host[dfm_host["hostname"] == selected_host] if not dfm_host.empty else pd.DataFrame()

        dfs_host = query_syslog(time_range, size=500)
        dfs_host = dfs_host[dfs_host["hostname"] == selected_host] if not dfs_host.empty else pd.DataFrame()

        if dfm_host.empty and dfs_host.empty:
            st.info(T["no_data_host"])
        else:
            st.markdown(f"##### {T['current_status']}")
            c1, c2, c3 = st.columns(3)
            
            latest_metrics = dfm_host.sort_values("timestamp").iloc[-1] if not dfm_host.empty else None
            
            cpu_curr = f"{latest_metrics['cpu_pct']*100:.1f}%" if latest_metrics is not None and pd.notna(latest_metrics['cpu_pct']) else "N/A"
            mem_curr = f"{latest_metrics['mem_used_pct']*100:.1f}%" if latest_metrics is not None and pd.notna(latest_metrics['mem_used_pct']) else "N/A"
            log_count = len(dfs_host)

            c1.metric("Current CPU", cpu_curr)
            c2.metric("Current Memory", mem_curr)
            c3.metric("Log Count", log_count)
            
            st.divider()

            st.markdown(f"### {T['cpu_mem_for_host']}")
            
            if not dfm_host.empty:
                df_resampled = dfm_host.set_index("timestamp").sort_index()
                df_resampled = df_resampled[["cpu_pct", "mem_used_pct"]].resample("1min").mean().fillna(0)

                cpu_mean = df_resampled["cpu_pct"].mean()
                cpu_std = df_resampled["cpu_pct"].std()
                
                if cpu_std > 0:
                    df_resampled["z_score"] = (df_resampled["cpu_pct"] - cpu_mean) / cpu_std
                else:
                    df_resampled["z_score"] = 0
                
                anomalies = df_resampled[df_resampled["z_score"] > 2.0].copy()
                
                col_chart, col_anom = st.columns([3, 1])
                
                with col_chart:
                    chart_df = df_resampled[["cpu_pct", "mem_used_pct"]] * 100
                    st.line_chart(chart_df)
                
                with col_anom:
                    st.write(f"**{T['anomaly']}**")
                    if not anomalies.empty:
                        st.error(f"Found {len(anomalies)} spikes!")
                        anom_display = (anomalies[["cpu_pct"]] * 100).rename(columns={"cpu_pct": "CPU %"})
                        st.dataframe(anom_display, height=200)
                    else:
                        st.success("Stable (No spikes > 2σ)")
            
            st.divider()

            st.markdown(f"### {T['last_logs']}")
            if not dfs_host.empty:
                st.dataframe(
                    dfs_host[["timestamp", "severity_name", "message"]]
                    .sort_values("timestamp", ascending=False)
                    .reset_index(drop=True),
                    use_container_width=True,
                    height=300
                )
            else:
                st.info("No logs.")
