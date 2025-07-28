#!/usr/bin/env python3
"""
ToolShell Honeypot - Sensor Component (Version 2.0)
Fast HTTP request capture with intelligent tagging and asynchronous analysis
"""

import os
import uuid
import json
import hashlib
from datetime import datetime
from flask import Flask, request, make_response
from functools import wraps
import re
import base64

app = Flask(__name__)

# Configuration
DATA_DIR = os.environ.get('DATA_DIR', './data')
IIS_HEADER = 'Microsoft-IIS/10.0'

# Directory paths
RAW_BODIES_DIR = os.path.join(DATA_DIR, 'raw_bodies')
EVENTS_NEW_DIR = os.path.join(DATA_DIR, 'events', 'new')
ACCESS_LOG = os.path.join(DATA_DIR, 'access.log')

# Ensure directories exist
for directory in [RAW_BODIES_DIR, EVENTS_NEW_DIR]:
    os.makedirs(directory, exist_ok=True)

def log_access(line):
    """Write to traditional access log"""
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    with open(ACCESS_LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')

class ThreatTagger:
    """Intelligent threat detection and tagging system"""
    
    @staticmethod
    def generate_ioc_tags(path, headers, method, args, body):
        """Generate high-confidence IOC tags based on specific patterns"""
        tags = []
        
        # Endpoint-based IOCs
        path_lower = path.lower()
        if path_lower in ['/_layouts/15/toolpane.aspx', '/_layouts/16/toolpane.aspx']:
            tags.append('IOC:ENDPOINT_TOOLPANE')
            
            # ToolPane specific parameter checks
            if 'displaymode' in args and args.get('displaymode', '').lower() == 'edit':
                tags.append('IOC:PARAM_DISPLAYMODE_EDIT')
            
            # Check for the 'a' parameter pattern
            for key, value in args.items():
                if value.lower() == '/toolpane.aspx':
                    tags.append('IOC:PARAM_TOOLPANE_REFERENCE')
                    break
        
        elif path_lower.startswith('/_layouts/') and path_lower.endswith('.aspx'):
            tags.append('IOC:ENDPOINT_LAYOUTS_ASPX')
        
        # Header-based IOCs
    referer = headers.get('Referer', '')
    if '/_layouts/SignOut.aspx' in referer:
            tags.append('IOC:REFERER_SIGNOUT')
        
        # User-Agent patterns
    ua = headers.get('User-Agent', '')
    if 'Firefox/120.0' in ua:
            tags.append('IOC:SUSPICIOUS_USER_AGENT')
        
        # Webshell probe patterns
        webshell_patterns = [
            '/spinstall0.aspx', '/spinstall.aspx', '/spinstall1.aspx', 
            '/info3.aspx', '/xxx.aspx'
        ]
        if any(pattern in path_lower for pattern in webshell_patterns):
            tags.append('IOC:WEBSHELL_PROBE')
        
        return tags
    
    @staticmethod
    def generate_pattern_tags(path, headers, method, args, body):
        """Generate pattern-based tags for known exploit signatures"""
        tags = []
        
        if method == 'POST' and body:
            body_str = body.decode('utf-8', errors='ignore')

            # R7 Metasploit exploit patterns
            if 'MSOTlPn_DWP' in body_str and 'CompressedDataTable' in body_str:
                tags.append('PATTERN:R7_PAYLOAD')
            
            # ViewState exploitation
            if b'__VIEWSTATE' in body:
                tags.append('PATTERN:VIEWSTATE_EXPLOIT')
                if 'ysoserial' in body_str.lower():
                    tags.append('PATTERN:YSOSERIAL')
            
            # PowerShell patterns
            ps_keywords = ['powershell', 'frombase64string', 'iex', 'invoke-expression']
            if any(keyword in body_str.lower() for keyword in ps_keywords):
                tags.append('PATTERN:POWERSHELL')
            
            # ASPX webshell patterns
            if any(pattern in body_str.lower() for pattern in ['<%@ page language', 'system.diagnostics.process']):
                tags.append('PATTERN:ASPX_WEBSHELL')
        
        return tags
    
    @staticmethod
    def generate_heuristic_tags(path, headers, method, args, body):
        """Generate heuristic tags based on anomaly detection"""
        tags = []
        
        # Large payload heuristic
        if body and len(body) > 1024:  # >1KB
            tags.append('HEURISTIC:LARGE_PAYLOAD')
        
        # Large Base64 heuristic
        if body:
            body_str = body.decode('utf-8', errors='ignore')
            b64_candidates = re.findall(r'([A-Za-z0-9+/=]{100,})', body_str)
            if b64_candidates:
                tags.append('HEURISTIC:LARGE_B64')
                if len(b64_candidates) > 3:
                    tags.append('HEURISTIC:MULTIPLE_B64')
        
        # Suspicious parameter count
        if len(args) > 10:
            tags.append('HEURISTIC:MANY_PARAMETERS')
        
        # Content-Type mismatches
        content_type = headers.get('Content-Type', '').lower()
        if method == 'POST':
            if not content_type:
                tags.append('HEURISTIC:MISSING_CONTENT_TYPE')
            elif 'multipart/form-data' in content_type and b'boundary=' not in body[:200]:
                tags.append('HEURISTIC:MALFORMED_MULTIPART')
        
        # Unusual request methods for SharePoint
        if method in ['PUT', 'DELETE', 'PATCH']:
            tags.append('HEURISTIC:UNUSUAL_METHOD')
        
        # Long URL paths
        if len(path) > 200:
            tags.append('HEURISTIC:LONG_PATH')
        
        return tags
    
    @classmethod
    def tag_request(cls, path, headers, method, args, body):
        """Comprehensive request tagging"""
        all_tags = []
        
        # High-confidence IOC detection
        all_tags.extend(cls.generate_ioc_tags(path, headers, method, args, body))
        
        # Known pattern detection
        all_tags.extend(cls.generate_pattern_tags(path, headers, method, args, body))
        
        # Heuristic anomaly detection
        all_tags.extend(cls.generate_heuristic_tags(path, headers, method, args, body))
        
        return list(set(all_tags))  # Remove duplicates

def log_and_respond(path, initial_tags=None):
    """
    Enhanced sensor function with tag-based detection and asynchronous analysis
    """
    req_id = str(uuid.uuid4())[:8]
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Extract request data
    headers = dict(request.headers)
    args = request.args.to_dict()
    body = request.get_data()
    remote_addr = request.remote_addr
    method = request.method
    
    # Generate comprehensive tags
    tags = initial_tags if initial_tags else []
    detected_tags = ThreatTagger.tag_request(path, headers, method, args, body)
    tags.extend(detected_tags)
    
    # Create event structure
    event_data = {
        'id': req_id,
        'timestamp': timestamp,
        'sensor_version': '2.0.0',
        'method': method,
        'path': path,
        'remote_addr': remote_addr,
        'headers': headers,
        'args': args,
        'tags': tags,
        'body_size': len(body) if body else 0,
        'body_hash': None
    }
    
    # Handle request body
    if body:
        # Calculate SHA256 hash for deduplication
        body_hash = hashlib.sha256(body).hexdigest()
        event_data['body_hash'] = body_hash
        
        # Save body with hash-based filename
        body_path = os.path.join(RAW_BODIES_DIR, f"{body_hash}.bin")
        if not os.path.exists(body_path):  # Avoid duplicates
            with open(body_path, 'wb') as f:
            f.write(body)
    
    # Save event for analyzer
    event_path = os.path.join(EVENTS_NEW_DIR, f"{req_id}.json")
    try:
        with open(event_path, 'w', encoding='utf-8') as f:
            json.dump(event_data, f, indent=2, ensure_ascii=False)
        print(f"[SENSOR] Event saved: {event_path}")
            except Exception as e:
        print(f"[SENSOR] ERROR saving event {req_id}: {e}")
    
    # Traditional access log
    user_agent = headers.get('User-Agent', '-')
    tags_str = ','.join(tags) if tags else '-'
    access_line = f'{timestamp} {remote_addr} "{method} {path} {request.environ.get("SERVER_PROTOCOL", "HTTP/1.1")}" {user_agent} [{tags_str}]'
    log_access(access_line)

    # Console output for monitoring
    print(f"[SENSOR] {req_id} {method} {path} from {remote_addr}")
    if tags:
        print(f"[SENSOR] Tags: {', '.join(tags)}")
        
        # Alert on high-priority tags
        alert_patterns = ['IOC:', 'PATTERN:R7_PAYLOAD', 'PATTERN:YSOSERIAL']
        if any(any(pattern in tag for pattern in alert_patterns) for tag in tags):
            print(f"[SENSOR] *** ALERT: High-priority threat detected! ***")

    # Fast response to attacker
    resp = make_response('OK', 200)
    resp.headers['Server'] = IIS_HEADER
    resp.headers['X-Powered-By'] = 'ASP.NET'
    return resp

# Decorator for honeypot routes
def honeypot_route(rule, **options):
    def decorator(f):
        @app.route(rule, **options)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator

# === SPECIFIC ENDPOINT ROUTES (IOC Generators) ===

@honeypot_route('/favicon.ico', methods=['GET'])
def favicon():
    return log_and_respond('/favicon.ico', initial_tags=['IOC:ENDPOINT_FAVICON'])

@honeypot_route('/_layouts/SignOut.aspx', methods=['GET', 'POST'])
def signout():
    return log_and_respond('/_layouts/SignOut.aspx', initial_tags=['IOC:ENDPOINT_SIGNOUT'])

@honeypot_route('/_layouts/15/ToolPane.aspx', methods=['GET', 'POST'])
def toolpane15():
    return log_and_respond('/_layouts/15/ToolPane.aspx', initial_tags=['IOC:ENDPOINT_TOOLPANE'])

@honeypot_route('/_layouts/16/ToolPane.aspx', methods=['GET', 'POST'])
def toolpane16():
    return log_and_respond('/_layouts/16/ToolPane.aspx', initial_tags=['IOC:ENDPOINT_TOOLPANE'])

@honeypot_route('/_layouts/15/ToolPane.aspx/', methods=['GET', 'POST'])
def toolpane15_trailing():
    # CVE-2025-53771 - trailing slash bypass
    return log_and_respond('/_layouts/15/ToolPane.aspx/', initial_tags=['IOC:ENDPOINT_TOOLPANE', 'IOC:CVE_2025_53771'])

@honeypot_route('/_layouts/16/ToolPane.aspx/', methods=['GET', 'POST'])
def toolpane16_trailing():
    # CVE-2025-53771 - trailing slash bypass
    return log_and_respond('/_layouts/16/ToolPane.aspx/', initial_tags=['IOC:ENDPOINT_TOOLPANE', 'IOC:CVE_2025_53771'])

@honeypot_route('/_controltemplates/15/AclEditor.ascx', methods=['GET', 'POST'])
def acleditor15():
    return log_and_respond('/_controltemplates/15/AclEditor.ascx', initial_tags=['IOC:ENDPOINT_ACLEDITOR'])

@honeypot_route('/_controltemplates/16/AclEditor.ascx', methods=['GET', 'POST'])
def acleditor16():
    return log_and_respond('/_controltemplates/16/AclEditor.ascx', initial_tags=['IOC:ENDPOINT_ACLEDITOR'])

# Webshell probe endpoints
@honeypot_route('/_layouts/15/spinstall0.aspx', methods=['GET', 'POST'])
def spinstall0_15():
    return log_and_respond('/_layouts/15/spinstall0.aspx', initial_tags=['IOC:WEBSHELL_PROBE'])

@honeypot_route('/_layouts/16/spinstall0.aspx', methods=['GET', 'POST'])
def spinstall0_16():
    return log_and_respond('/_layouts/16/spinstall0.aspx', initial_tags=['IOC:WEBSHELL_PROBE'])

@honeypot_route('/_layouts/15/spinstall.aspx', methods=['GET', 'POST'])
def spinstall_15():
    return log_and_respond('/_layouts/15/spinstall.aspx', initial_tags=['IOC:WEBSHELL_PROBE'])

@honeypot_route('/_layouts/15/spinstall1.aspx', methods=['GET', 'POST'])
def spinstall1_15():
    return log_and_respond('/_layouts/15/spinstall1.aspx', initial_tags=['IOC:WEBSHELL_PROBE'])

@honeypot_route('/_layouts/15/info3.aspx', methods=['GET', 'POST'])
def info3_15():
    return log_and_respond('/_layouts/15/info3.aspx', initial_tags=['IOC:WEBSHELL_PROBE'])

@honeypot_route('/_layouts/15/xxx.aspx', methods=['GET', 'POST'])
def xxx_15():
    return log_and_respond('/_layouts/15/xxx.aspx', initial_tags=['IOC:WEBSHELL_PROBE'])

# === CATCH-ALL ROUTE (Heuristic Detection) ===
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_all(path):
    return log_and_respond('/' + path, initial_tags=['HEURISTIC:UNKNOWN_ENDPOINT'])

def setup_directories():
    """Ensure all required directories exist"""
    dirs = [DATA_DIR, EVENTS_NEW_DIR, RAW_BODIES_DIR]
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
        print(f"[SENSOR] Directory ready: {directory}")

if __name__ == '__main__':
    import ssl
    print("[SENSOR] ToolShell Honeypot Sensor v2.0 starting...")
    print(f"[SENSOR] Data directory: {DATA_DIR}")
    
    # Setup directories first
    setup_directories()
    
    print(f"[SENSOR] Raw bodies: {RAW_BODIES_DIR}")
    print(f"[SENSOR] Events queue: {EVENTS_NEW_DIR}")
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=443, ssl_context=context, debug=False) 