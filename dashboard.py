import os
import json
import streamlit as st
from glob import glob

DATA_DIR = os.environ.get('DATA_DIR', './data')
ACCESS_LOG = os.path.join(DATA_DIR, 'access.log')

st.set_page_config(page_title='Honeypot Dashboard', layout='wide')
st.title('Honeypot Zero-Day Dashboard')

# Load all JSON logs
json_files = sorted(glob(os.path.join(DATA_DIR, '*-headers.json')), reverse=True)
logs = []
for jf in json_files:
    with open(jf, 'r', encoding='utf-8') as f:
        logs.append(json.load(f))

# IOC filter
ioc_options = set()
for log in logs:
    if log.get('ioc'):
        ioc_options.update(log['ioc'])
ioc_options = sorted(ioc_options)
selected_iocs = st.multiselect('Filter by IOC', ioc_options)

# Filter logs by selected IOCs
if selected_iocs:
    filtered_logs = [log for log in logs if log.get('ioc') and any(i in log['ioc'] for i in selected_iocs)]
else:
    filtered_logs = logs

if filtered_logs:
    st.write(f"{len(filtered_logs)} requests logged.")
    # Highlight IOC rows
    def highlight_ioc(row):
        return ['background-color: #ffcccc' if row['ioc'] else '' for _ in row]
    import pandas as pd
    df = pd.DataFrame(filtered_logs)
    st.dataframe(df.style.apply(highlight_ioc, axis=1))
    # Download body and zip
    for log in filtered_logs:
        st.markdown(f"**ID:** {log['id']} | **Path:** {log['path']} | **Method:** {log['method']} | **Time:** {log['timestamp']}")
        if log.get('ioc'):
            st.warning(f"IOC detected: {', '.join(log['ioc'])}")
        if log.get('body_file'):
            bin_path = os.path.join(DATA_DIR, log['body_file'])
            with open(bin_path, 'rb') as f:
                st.download_button(f"Download body ({log['body_file']})", f, file_name=log['body_file'])
    # Download latest ZIP (today)
    from datetime import date
    zip_path = os.path.join(DATA_DIR, f'{date.today().isoformat()}.zip')
    if os.path.exists(zip_path):
        with open(zip_path, 'rb') as f:
            st.download_button('Download today\'s ZIP archive', f, file_name=f'{date.today().isoformat()}.zip')
else:
    st.info('No logs found.')

# Show access.log
st.header('Access Log (Apache/Nginx style)')
if os.path.exists(ACCESS_LOG):
    with open(ACCESS_LOG, 'r', encoding='utf-8') as f:
        st.text_area('access.log', f.read(), height=200)
else:
    st.info('No access.log found.') 