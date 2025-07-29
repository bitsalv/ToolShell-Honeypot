#!/usr/bin/env python3
"""
ToolShell Honeypot - Dashboard
Updated dashboard for the new sensor/analyzer architecture
"""

import streamlit as st
import pandas as pd
import json
import os
import time
from datetime import datetime, timedelta
import requests

# Configuration
DATA_DIR = os.getenv('DATA_DIR', './data')
EVENTS_PROCESSED_DIR = os.path.join(DATA_DIR, 'events', 'processed')
EVENTS_NEW_DIR = os.path.join(DATA_DIR, 'events', 'new')
EVENTS_ERROR_DIR = os.path.join(DATA_DIR, 'events', 'error')
RAW_BODIES_DIR = os.path.join(DATA_DIR, 'raw_bodies')
ACCESS_LOG_PATH = os.path.join(DATA_DIR, 'access.log')

# Page config
st.set_page_config(
    page_title="Toolshell Honeypot",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for modern, minimal design
st.markdown("""
<style>
    /* Hide Streamlit default elements */
    #MainMenu {visibility: hidden;}
    .stDeployButton {display: none;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Clean sidebar styling */
    .sidebar-content {
        padding: 0.5rem;
        background: #fafafa;
        border-radius: 6px;
        margin-bottom: 0.5rem;
    }
    
    /* Slim color legend */
    .color-legend {
        background: #ffffff;
        padding: 12px;
        border-radius: 6px;
        border: 1px solid #e1e5e9;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .color-legend h4 {
        margin: 0 0 8px 0;
        font-size: 14px;
        font-weight: 600;
        color: #374151;
    }
    
    /* Slim tag styling */
    .tag-ioc { 
        background: linear-gradient(135deg, #ef4444, #dc2626);
        color: white; 
        padding: 2px 6px; 
        border-radius: 4px; 
        font-size: 0.75em; 
        font-weight: 500;
        margin: 1px;
        display: inline-block;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    .tag-pattern { 
        background: linear-gradient(135deg, #f97316, #ea580c);
        color: white; 
        padding: 2px 6px; 
        border-radius: 4px; 
        font-size: 0.75em; 
        font-weight: 500;
        margin: 1px;
        display: inline-block;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    .tag-heuristic { 
        background: linear-gradient(135deg, #eab308, #ca8a04);
        color: white; 
        padding: 2px 6px; 
        border-radius: 4px; 
        font-size: 0.75em; 
        font-weight: 500;
        margin: 1px;
        display: inline-block;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    
    /* Status indicators */
    .status-processed { color: #059669; font-weight: 500; }
    .status-pending { color: #6b7280; font-weight: 500; }
    .status-error { color: #dc2626; font-weight: 500; }
    
    /* Slim metric cards */
    .metric-card {
        background: linear-gradient(135deg, #ffffff, #f9fafb);
        padding: 16px;
        border-radius: 8px;
        border: 1px solid #e5e7eb;
        text-align: center;
        margin: 4px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-card h3 {
        margin: 0 0 4px 0;
        font-size: 24px;
        font-weight: 700;
        color: #111827;
    }
    .metric-card p {
        margin: 0;
        font-size: 12px;
        color: #6b7280;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    /* Clean table styling */
    .dataframe {
        border: none !important;
        font-size: 0.9em;
    }
    .dataframe thead tr th {
        background: #f8fafc !important;
        border-bottom: 1px solid #e2e8f0 !important;
        color: #374151 !important;
        font-weight: 600 !important;
        font-size: 0.8em !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .dataframe tbody tr:hover {
        background: #f1f5f9 !important;
    }
    


    
    /* Sidebar title */
    .main-title {
        font-size: 1.2rem;
        font-weight: 700;
        color: #111827;
        margin: 0 0 16px 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'dashboard'

def load_events():
    """Load events from processed and new directories"""
    events = []
    
    # Load processed events
    if os.path.exists(EVENTS_PROCESSED_DIR):
        for filename in os.listdir(EVENTS_PROCESSED_DIR):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(EVENTS_PROCESSED_DIR, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        event = json.load(f)
                        event['_status'] = 'processed'
                        event['_filename'] = filename
                        events.append(event)
                except Exception as e:
                    st.error(f"Error loading {filename}: {e}")
    
    # Load pending events
    if os.path.exists(EVENTS_NEW_DIR):
        for filename in os.listdir(EVENTS_NEW_DIR):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(EVENTS_NEW_DIR, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        event = json.load(f)
                        event['_status'] = 'pending'
                        event['_filename'] = filename
                        events.append(event)
                except Exception as e:
                    st.error(f"Error loading {filename}: {e}")
    
    # Sort by timestamp (newest first)
    events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return events

def format_tags_html(tags):
    """Format tags with color coding"""
    if not tags:
        return ""
    
    html_tags = []
    for tag in tags:
        if tag.startswith('IOC:'):
            html_tags.append(f'<span class="tag-ioc">{tag}</span>')
        elif tag.startswith('PATTERN:'):
            html_tags.append(f'<span class="tag-pattern">{tag}</span>')
        elif tag.startswith('HEURISTIC:'):
            html_tags.append(f'<span class="tag-heuristic">{tag}</span>')
        else:
            html_tags.append(f'<span class="tag-ioc">{tag}</span>')
    
    return ' '.join(html_tags)

def render_sidebar():
    """Render sidebar with navigation and tag legend"""
    with st.sidebar:
        st.markdown('<div class="main-title">🍯 Toolshell Honeypot</div>', unsafe_allow_html=True)
        
        if st.button("🏠 Dashboard", use_container_width=True, 
                    type="primary" if st.session_state.current_page == 'dashboard' else "secondary"):
            st.session_state.current_page = 'dashboard'
            st.rerun()
            
        if st.button("🔍 Analysis", use_container_width=True,
                    type="primary" if st.session_state.current_page == 'analysis' else "secondary"):
            st.session_state.current_page = 'analysis'
            st.rerun()
            
        if st.button("📥 Export", use_container_width=True,
                    type="primary" if st.session_state.current_page == 'export' else "secondary"):
            st.session_state.current_page = 'export'
            st.rerun()
        
        st.markdown("---")
        
        # Slim Color Legend
        st.markdown("""
        <div class="color-legend">
            <h4>🎨 Tag Colors</h4>
            <span class="tag-ioc">IOC</span>
            <span class="tag-pattern">PATTERN</span>
            <span class="tag-heuristic">HEURISTIC</span>
            <hr style="margin: 8px 0; border: none; border-top: 1px solid #e5e7eb;">
            <div style="font-size: 0.75em;">
                <span class="status-processed">● Processed</span><br>
                <span class="status-pending">● Pending</span><br>
                <span class="status-error">● Error</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_homepage(events):
    """Render homepage with compact stats and full events table"""
    st.markdown('<div class="main-title">🏠 Dashboard Overview</div>', unsafe_allow_html=True)
    
    # Slim metrics cards
    col1, col2, col3, col4 = st.columns(4)
    
    total_events = len(events)
    ioc_events = len([e for e in events if any(tag.startswith('IOC:') for tag in e.get('tags', []))])
    r7_events = len([e for e in events if any('R7_PAYLOAD' in tag for tag in e.get('tags', []))])
    processed_events = len([e for e in events if e.get('_status') == 'processed'])
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{total_events}</h3>
            <p>Total Events</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{ioc_events}</h3>
            <p>IOC Alerts</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{r7_events}</h3>
            <p>R7 Exploits</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{processed_events}</h3>
            <p>Processed</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Full events table with colors
    st.markdown("## 📊 All Events")
    
    if events:
        # Prepare table data
        table_data = []
        for event in events:
            tags_html = format_tags_html(event.get('tags', []))
            status_class = f"status-{event.get('_status', 'pending')}"
            
            table_data.append({
                'Time': event.get('timestamp', '').replace('T', ' ').replace('Z', ''),
                'Method': event.get('method', ''),
                'Path': event.get('path', '')[:50] + ('...' if len(event.get('path', '')) > 50 else ''),
                'IP': event.get('remote_addr', ''),
                'Tags': tags_html,
                'Status': f'<span class="{status_class}">{event.get("_status", "pending").title()}</span>',
                'Size': f"{event.get('body_size', 0)} B"
            })
        
        # Convert to DataFrame
        df = pd.DataFrame(table_data)
        
        # Display table with HTML formatting
        st.markdown(df.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.info("No events found. Start generating traffic to see data.")

def render_event_analysis(events):
    """Render detailed event analysis with filtering"""
    
    if not events:
        st.info("No events to analyze.")
        return
    
    # Filtering options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Tag filter
        all_tags = set()
        for event in events:
            all_tags.update(event.get('tags', []))
        
        selected_tags = st.multiselect("Filter by Tags:", sorted(list(all_tags)))
    
    with col2:
        # Status filter
        statuses = ['All'] + list(set(e.get('_status', 'pending') for e in events))
        selected_status = st.selectbox("Status:", statuses)
    
    with col3:
        # Method filter
        methods = ['All'] + list(set(e.get('method', '') for e in events))
        selected_method = st.selectbox("HTTP Method:", methods)
    
    # Apply filters
    filtered_events = events
    
    if selected_tags:
        filtered_events = [e for e in filtered_events if any(tag in e.get('tags', []) for tag in selected_tags)]
    
    if selected_status != 'All':
        filtered_events = [e for e in filtered_events if e.get('_status') == selected_status]
    
    if selected_method != 'All':
        filtered_events = [e for e in filtered_events if e.get('method') == selected_method]
    
    st.markdown(f"### Showing {len(filtered_events)} of {len(events)} events")
    
    # Events list with expandable details
    for i, event in enumerate(filtered_events):
        with st.expander(f"Event {i+1}: {event.get('method', '')} {event.get('path', '')} - {event.get('timestamp', '')}"):
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Request Info:**")
                st.json({
                    'timestamp': event.get('timestamp'),
                    'method': event.get('method'),
                    'path': event.get('path'),
                    'remote_addr': event.get('remote_addr'),
                    'headers': event.get('headers', {}),
                    'args': event.get('args', {})
                })
            
            with col2:
                st.markdown("**Analysis Results:**")
                if event.get('_status') == 'processed':
                    analysis = event.get('deep_analysis_results', {})
                    st.json(analysis)
                else:
                    st.info("Analysis pending...")
            
            # Tags display
            if event.get('tags'):
                st.markdown("**Tags:**")
                st.markdown(format_tags_html(event.get('tags')), unsafe_allow_html=True)

def render_export_section(events):
    """Render export and download section"""
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Reports")
        
        if st.button("📄 Download Events (JSON)", use_container_width=True):
            events_json = json.dumps(events, indent=2)
            st.download_button(
                label="💾 events.json",
                data=events_json,
                file_name=f"honeypot_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        if st.button("📈 Download Events (CSV)", use_container_width=True):
            if events:
                df = pd.DataFrame([{
                    'timestamp': e.get('timestamp'),
                    'method': e.get('method'),
                    'path': e.get('path'),
                    'ip': e.get('remote_addr'),
                    'tags': ','.join(e.get('tags', [])),
                    'status': e.get('_status'),
                    'body_size': e.get('body_size', 0)
                } for e in events])
                
                csv = df.to_csv(index=False)
                st.download_button(
                    label="💾 events.csv",
                    data=csv,
                    file_name=f"honeypot_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    
    with col2:
        st.markdown("### 📁 Raw Data")
        
        # List available body files
        if os.path.exists(RAW_BODIES_DIR):
            body_files = [f for f in os.listdir(RAW_BODIES_DIR) if f.endswith('.bin')]
            if body_files:
                st.markdown(f"**{len(body_files)} body files available**")
                selected_body = st.selectbox("Select body file:", body_files)
                
                if selected_body and st.button("📥 Download Body File"):
                    body_path = os.path.join(RAW_BODIES_DIR, selected_body)
                    with open(body_path, 'rb') as f:
                        st.download_button(
                            label=f"💾 {selected_body}",
                            data=f.read(),
                            file_name=selected_body,
                            mime="application/octet-stream"
                        )
            else:
                st.info("No body files found")
    
    # Access log viewer
    st.markdown("---")
    st.markdown("### 📋 Access Log")
    
    if os.path.exists(ACCESS_LOG_PATH):
        with open(ACCESS_LOG_PATH, 'r') as f:
            log_content = f.read()
        
        st.text_area("Access Log Content:", log_content, height=300)
        
        st.download_button(
            label="📥 Download Access Log",
            data=log_content,
            file_name=f"access_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
    else:
        st.info("No access log found")

# Main application
def main():
    # Render sidebar
    render_sidebar()
    
    # Load events
    events = load_events()
    
    # Render current page based on sidebar navigation
    if st.session_state.current_page == 'dashboard':
        render_homepage(events)
    elif st.session_state.current_page == 'analysis':
        render_event_analysis(events)
    elif st.session_state.current_page == 'export':
        render_export_section(events)

if __name__ == "__main__":
    main() 