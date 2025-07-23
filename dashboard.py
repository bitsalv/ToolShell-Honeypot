import os
import json
import streamlit as st
from glob import glob
from datetime import date
import pandas as pd
import io
import zipfile
import csv

DATA_DIR = os.environ.get('DATA_DIR', './data')
ACCESS_LOG = os.path.join(DATA_DIR, 'access.log')

st.set_page_config(page_title='ToolShell Honeypot', layout='wide')
st.header('ToolShell Honeypot')

# === SUMMARY SECTION ===
st.subheader("Summary")
json_files = sorted(glob(os.path.join(DATA_DIR, '*-headers.json')), reverse=True)
logs = []
for jf in json_files:
    with open(jf, 'r', encoding='utf-8') as f:
        logs.append(json.load(f))

ioc_logs = [log for log in logs if log.get('ioc')]
all_iocs = []
for log in ioc_logs:
    if log.get('ioc'):
        all_iocs.extend(log['ioc'])
unique_iocs = list(dict.fromkeys(all_iocs))  # preserve order, unique

st.markdown(f"""
<div style="display: flex; gap: 2em;">
  <div><b>Total requests:</b> {len(logs)}</div>
  <div><b>Requests with IOC:</b> {len(ioc_logs)}</div>
  <div><b>Recent IOCs:</b> {', '.join(unique_iocs[:10]) if unique_iocs else 'None'}</div>
</div>
""", unsafe_allow_html=True)

# === IOC FILTER SECTION ===
st.subheader("IOC Filter")
ioc_counts = {}
for ioc in all_iocs:
    ioc_counts[ioc] = ioc_counts.get(ioc, 0) + 1
ioc_options = [f"{ioc} ({ioc_counts[ioc]})" for ioc in sorted(ioc_counts)]
selected_iocs = st.multiselect('Show only requests containing these IOCs:', options=ioc_options)
selected_iocs_raw = [ioc.split(' (')[0] for ioc in selected_iocs]

def log_has_selected_ioc(log):
    if not selected_iocs_raw:
        return True
    return log.get('ioc') and any(i in log['ioc'] for i in selected_iocs_raw)

filtered_logs = [log for log in logs if log_has_selected_ioc(log)]

# === REQUESTS TABLE SECTION ===
st.subheader("Requests Table")
if filtered_logs:
    table_data = []
    for log in filtered_logs:
        table_data.append({
            "Time": log.get("timestamp"),
            "Method": log.get("method"),
            "Path": log.get("path"),
            "IP": log.get("remote_addr", "-"),
            "IOC": ", ".join(log.get("ioc") or []),
            "YARA": ", ".join(log.get("yara_matches") or []),
            "PS/Base64": "Yes" if log.get("powershell_suspect") else ""
        })
    df = pd.DataFrame(table_data)
    def highlight_row(row):
        if row['YARA']:
            return ['background-color: #ffe066'] * len(row)
        elif row['PS/Base64']:
            return ['background-color: #fff3cd'] * len(row)
        elif row['IOC']:
            return ['background-color: #ffcccc'] * len(row)
        else:
            return [''] * len(row)
    st.dataframe(df.style.apply(highlight_row, axis=1), use_container_width=True)

    # === REQUEST DETAILS SECTION ===
    st.subheader("Request Details")
    for idx, log in enumerate(filtered_logs):
        with st.expander(f"Details for request {log['id']} ({log['timestamp']})"):
            st.markdown(f"**Method:** {log['method']}")
            st.markdown(f"**Path:** {log['path']}")
            st.markdown(f"**Remote address:** {log.get('remote_addr', '-')}")
            # IOC badges
            if log.get('ioc'):
                st.markdown("**IOC Detected:** " + " ".join([
                    f"<span style='background-color:#ffcccc; color:#b30000; padding:2px 6px; border-radius:6px; margin-right:4px'>{ioc}</span>"
                    for ioc in log['ioc']
                ]), unsafe_allow_html=True)
            else:
                st.markdown("**IOC Detected:** <span style='color:green'>None</span>", unsafe_allow_html=True)
            # YARA badges
            if log.get('yara_matches'):
                st.markdown("**YARA Matches:** " + " ".join([
                    f"<span style='background-color:#ffe066; color:#b36b00; padding:2px 6px; border-radius:6px; margin-right:4px'>{rule}</span>"
                    for rule in log['yara_matches']
                ]), unsafe_allow_html=True)
            else:
                st.markdown("**YARA Matches:** <span style='color:gray'>None</span>", unsafe_allow_html=True)
            # PowerShell/Base64 detection
            if log.get('powershell_suspect'):
                st.markdown("**PowerShell/Base64 Suspect:** <span style='background-color:#fff3cd; color:#856404; padding:2px 6px; border-radius:6px;'>Yes</span>", unsafe_allow_html=True)
                st.markdown("**Patterns found:** " + (", ".join(log.get('powershell_patterns', [])) or '<span style="color:gray">None</span>'), unsafe_allow_html=True)
                st.markdown(f"**Decoded base64 payloads:** {log.get('decoded_base64_count', 0)}")
                if log.get('yara_matches_decoded'):
                    st.markdown("**YARA Matches (decoded):** " + " ".join([
                        f"<span style='background-color:#ffe066; color:#b36b00; padding:2px 6px; border-radius:6px; margin-right:4px'>{rule}</span>"
                        for rule in log['yara_matches_decoded']
                    ]), unsafe_allow_html=True)
            st.markdown("**Headers:**")
            st.json(log.get('headers', {}))
            st.markdown("**Query args:**")
            st.json(log.get('args', {}))
            # Download buttons
            st.markdown("**Downloads:**")
            col1, col2 = st.columns(2)
            with col1:
                # Download body
                if log.get('body_file'):
                    bin_path = os.path.join(DATA_DIR, log['body_file'])
                    if os.path.exists(bin_path):
                        with open(bin_path, 'rb') as f:
                            st.download_button("Download body", f, file_name=log['body_file'], key=f"body_{log['id']}")
            with col2:
                # Download JSON
                json_path = os.path.join(DATA_DIR, f"{log['id']}-headers.json")
                if os.path.exists(json_path):
                    with open(json_path, 'rb') as f:
                        st.download_button("Download JSON", f, file_name=f"{log['id']}-headers.json", key=f"json_{log['id']}")
            # Show body preview (hex and, if text, as string)
            if log.get('body_file'):
                bin_path = os.path.join(DATA_DIR, log['body_file'])
                if os.path.exists(bin_path):
                    with open(bin_path, 'rb') as f:
                        body_bytes = f.read(2048)  # up to 2KB preview
                    content_type = log.get('headers', {}).get('Content-Type', '').lower()
                    is_textual = any(
                        t in content_type
                        for t in ['text', 'json', 'xml', 'x-www-form-urlencoded']
                    )
                    st.markdown("**Body preview (first 2KB, hex):**")
                    st.code(body_bytes.hex())
                    if is_textual:
                        try:
                            st.markdown("**Body preview (as text):**")
                            st.code(body_bytes.decode('utf-8', errors='replace'))
                        except Exception:
                            st.info("Could not decode body as text.")
else:
    st.info('No logs found.')

# === GLOBAL DOWNLOADS SECTION ===
st.header("Global Downloads")
# Download ZIP of all .bin (already present)
zip_path = os.path.join(DATA_DIR, f"{date.today().isoformat()}.zip")
if os.path.exists(zip_path):
    with open(zip_path, 'rb') as f:
        st.download_button("Download today's ZIP archive", f, file_name=f"{date.today().isoformat()}.zip", key="zip_global")

# Download all JSON logs as ZIP
json_zip_bytes = io.BytesIO()
with zipfile.ZipFile(json_zip_bytes, 'w', zipfile.ZIP_DEFLATED) as zf:
    for jf in json_files:
        zf.write(jf, arcname=os.path.basename(jf))
json_zip_bytes.seek(0)
st.download_button(
    "Download all JSON logs (ZIP)",
    json_zip_bytes,
    file_name="all_json_logs.zip",
    mime="application/zip",
    key="json_zip_global"
)

# --- EXPORT CSV SECTION ---
csv_bytes = io.StringIO()
fieldnames = ["id", "timestamp", "method", "path", "remote_addr", "ioc", "yara_matches", "powershell_suspect", "powershell_patterns", "decoded_base64_count", "yara_matches_decoded", "headers", "args", "body_file"]
writer = csv.DictWriter(csv_bytes, fieldnames=fieldnames)
writer.writeheader()
for log in logs:
    writer.writerow({
        "id": log.get("id"),
        "timestamp": log.get("timestamp"),
        "method": log.get("method"),
        "path": log.get("path"),
        "remote_addr": log.get("remote_addr"),
        "ioc": ";".join(log.get("ioc") or []),
        "yara_matches": ";".join(log.get("yara_matches") or []),
        "powershell_suspect": log.get("powershell_suspect", False),
        "powershell_patterns": ";".join(log.get("powershell_patterns") or []),
        "decoded_base64_count": log.get("decoded_base64_count", 0),
        "yara_matches_decoded": ";".join(log.get("yara_matches_decoded") or []),
        "headers": json.dumps(log.get("headers", {})),
        "args": json.dumps(log.get("args", {})),
        "body_file": log.get("body_file", "")
    })
st.download_button(
    "Download all data (CSV)",
    csv_bytes.getvalue(),
    file_name="all_requests.csv",
    mime="text/csv",
    key="csv_global"
)

# === ACCESS LOG SECTION ===
st.header('Access Log (Apache/Nginx style)')
if os.path.exists(ACCESS_LOG):
    with open(ACCESS_LOG, 'r', encoding='utf-8') as f:
        access_log_content = f.read()
    st.text_area('access.log', access_log_content, height=300, key="accesslog", help="Full access.log", disabled=True)
    st.download_button("Download access.log", access_log_content, file_name="access.log", key="accesslog_dl")
else:
    st.info('No access.log found.') 