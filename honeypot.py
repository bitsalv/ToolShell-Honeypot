import os
import uuid
import json
import zipfile
from datetime import datetime, date
from flask import Flask, request, make_response
from functools import wraps
import yara
import re
import base64

app = Flask(__name__)
DATA_DIR = os.environ.get('DATA_DIR', './data')
IIS_HEADER = 'Microsoft-IIS/10.0'
ACCESS_LOG = os.path.join(DATA_DIR, 'access.log')

YARA_RULES_PATH = os.environ.get('YARA_RULES_PATH', '/app/yara_rules/')
def load_yara_rules():
    rule_files = [os.path.join(YARA_RULES_PATH, f) for f in os.listdir(YARA_RULES_PATH) if f.endswith('.yar')]
    if rule_files:
        return yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
    return None

yara_rules = load_yara_rules()

os.makedirs(DATA_DIR, exist_ok=True)

def log_access(line):
    with open(ACCESS_LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')

def rotate_zip():
    today = date.today().isoformat()
    zip_path = os.path.join(DATA_DIR, f'{today}.zip')
    return zip_path

def detect_iocs(path, headers, method, args, body):
    iocs = []
    # Endpoint ToolPane exploit
    if path.lower() in [
        '/_layouts/15/toolpane.aspx',
        '/_layouts/16/toolpane.aspx'
    ]:
        iocs.append('ToolPane exploit endpoint')
        if 'displaymode' in args and args.get('displaymode','').lower() == 'edit':
            iocs.append('DisplayMode=Edit')
        if 'a' in args and args.get('a','').lower() == '/toolpane.aspx':
            iocs.append('a=/ToolPane.aspx')
    # Referer
    referer = headers.get('Referer', '')
    if '/_layouts/SignOut.aspx' in referer:
        iocs.append('Referer SignOut.aspx')
    # User-Agent
    ua = headers.get('User-Agent', '')
    if 'Firefox/120.0' in ua:
        iocs.append('Suspicious User-Agent')
    # Webshell probing
    if any(p in path.lower() for p in [
        '/spinstall0.aspx', '/spinstall.aspx', '/spinstall1.aspx', '/info3.aspx', '/xxx.aspx'
    ]):
        iocs.append('Webshell probe')
    # ViewState in body
    if method == 'POST' and b'__VIEWSTATE' in body:
        iocs.append('ViewState payload')
    return iocs

def detect_potential_powershell_base64(body_bytes):
    body_str = body_bytes.decode('utf-8', errors='ignore')
    # Ampliamento pattern PowerShell
    ps_patterns = [
        "powershell", "FromBase64String", "IEX", "Invoke-Expression", "Invoke-WebRequest",
        "New-Object Net.WebClient", "Set-ExecutionPolicy", "Add-MpPreference", "Start-Process",
        "-EncodedCommand", "-Command", "-c", "[System.Convert]::FromBase64String", "[Text.Encoding]",
        "DownloadString", "cmd.exe /c powershell", "Invoke-DownloadFile"
    ]
    found_patterns = [p for p in ps_patterns if p.lower() in body_str.lower()]
    # Cerca anche pattern offuscati (es. I`E`X, concatenazione, char codes, variabili)
    if re.search(r'I[`\-]?E[`\-]?X', body_str, re.IGNORECASE):
        found_patterns.append('IEX (obfuscated)')
    if re.search(r'("I"\s*\+\s*"EX")|(\'I\'\s*\+\s*\'EX\')', body_str, re.IGNORECASE):
        found_patterns.append('IEX (concatenated)')
    if re.search(r'\[char\]\d+\s*\+\s*\[char\]\d+', body_str):
        found_patterns.append('Char code PowerShell')
    if re.search(r'\$[a-zA-Z0-9_]+\s*=\s*["\']IEX["\']', body_str):
        found_patterns.append('IEX (variable assignment)')
    if re.search(r'cmd\.exe\s*/c\s*powershell', body_str, re.IGNORECASE):
        found_patterns.append('cmd.exe /c powershell')
    if re.search(r'IEX\s*\(', body_str, re.IGNORECASE):
        found_patterns.append('IEX (function call)')
    if re.search(r'Get-Content', body_str, re.IGNORECASE):
        found_patterns.append('Get-Content pipeline')
    if re.search(r'Invoke-Obfuscation', body_str, re.IGNORECASE):
        found_patterns.append('Invoke-Obfuscation artifact')
    # Cerca stringhe base64 lunghe (anche senza -EncodedCommand)
    b64_candidates = re.findall(r'([A-Za-z0-9+/=]{40,})', body_str)
    decoded = []
    # Decodifica base64 sia UTF-8 che UTF-16LE
    for b64 in b64_candidates:
        for encoding in ['utf-8', 'utf-16le']:
            try:
                decoded_bytes = base64.b64decode(b64)
                decoded_str = decoded_bytes.decode(encoding, errors='ignore')
                # Heuristics: decoded must be mostly printable or contain powershell keywords
                if any(p.lower() in decoded_str.lower() for p in ps_patterns) or sum(c.isprintable() for c in decoded_str) > 10:
                    decoded.append(decoded_bytes)
                    if encoding == 'utf-16le':
                        found_patterns.append('Base64 UTF-16LE decoded')
                    break
            except Exception:
                continue
    suspect = bool(found_patterns or decoded)
    return suspect, found_patterns, decoded

def log_and_respond(path):
    req_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat() + 'Z'
    headers = dict(request.headers)
    args = request.args.to_dict()
    body = request.get_data()
    iocs = detect_iocs(path, headers, request.method, args, body)
    log = {
        'id': req_id,
        'timestamp': now,
        'method': request.method,
        'path': path,
        'headers': headers,
        'remote_addr': request.remote_addr,
        'args': args,
        'body_file': None,
        'ioc': iocs if iocs else None
    }
    # Save POST body
    if body:
        bin_path = os.path.join(DATA_DIR, f'{req_id}-body.bin')
        with open(bin_path, 'wb') as f:
            f.write(body)
        log['body_file'] = os.path.basename(bin_path)
        # YARA scan
        yara_matches = []
        if yara_rules:
            try:
                matches = yara_rules.match(bin_path)
                yara_matches = [m.rule for m in matches]
            except Exception as e:
                print(f"YARA scan error: {e}")
        if yara_matches:
            log['yara_matches'] = yara_matches
        # PowerShell/base64 detection and YARA on decoded
        ps_suspect, ps_patterns, decoded_payloads = detect_potential_powershell_base64(body)
        if ps_suspect:
            log['powershell_suspect'] = True
            if ps_patterns:
                log['powershell_patterns'] = ps_patterns
            log['decoded_base64_count'] = len(decoded_payloads)
            yara_matches_decoded = []
            for idx, decoded in enumerate(decoded_payloads):
                tmp_decoded_path = os.path.join(DATA_DIR, f'{req_id}-decoded-{idx}.bin')
                with open(tmp_decoded_path, 'wb') as f:
                    f.write(decoded)
                if yara_rules:
                    try:
                        matches = yara_rules.match(tmp_decoded_path)
                        yara_matches_decoded.extend([m.rule for m in matches])
                    except Exception as e:
                        print(f"YARA scan error (decoded): {e}")
                os.remove(tmp_decoded_path)
            if yara_matches_decoded:
                log['yara_matches_decoded'] = list(set(yara_matches_decoded))
        # Update daily ZIP
        zip_path = rotate_zip()
        with zipfile.ZipFile(zip_path, 'a') as z:
            z.write(bin_path, arcname=os.path.basename(bin_path))
    # Salva log JSON
    json_path = os.path.join(DATA_DIR, f'{req_id}-headers.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(log, f, indent=2)
    # Log access.log stile Apache
    access_line = f'{now} {request.remote_addr} "{request.method} {path} {request.environ.get("SERVER_PROTOCOL")}" {headers.get("User-Agent","-")} {log["ioc"] if log["ioc"] else "-"}'
    log_access(access_line)
    # Log su stdout
    print(json.dumps(log, indent=2))
    if iocs:
        print(f'*** ALERT: IOC detected! {iocs} ***')
    # Risposta
    resp = make_response('OK', 200)
    resp.headers['Server'] = IIS_HEADER
    return resp

# Decorator for sensitive endpoints

def honeypot_route(rule, **options):
    def decorator(f):
        @app.route(rule, **options)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Dedicated endpoints
@honeypot_route('/favicon.ico', methods=['GET'])
def favicon():
    return log_and_respond('/favicon.ico')

@honeypot_route('/_layouts/SignOut.aspx', methods=['GET', 'POST'])
def signout():
    return log_and_respond('/_layouts/SignOut.aspx')

@honeypot_route('/_layouts/15/ToolPane.aspx', methods=['GET', 'POST'])
def toolpane15():
    return log_and_respond('/_layouts/15/ToolPane.aspx')

@honeypot_route('/_layouts/16/ToolPane.aspx', methods=['GET', 'POST'])
def toolpane16():
    return log_and_respond('/_layouts/16/ToolPane.aspx')

@honeypot_route('/_layouts/15/spinstall0.aspx', methods=['GET', 'POST'])
def spinstall0_15():
    return log_and_respond('/_layouts/15/spinstall0.aspx')

@honeypot_route('/_layouts/16/spinstall0.aspx', methods=['GET', 'POST'])
def spinstall0_16():
    return log_and_respond('/_layouts/16/spinstall0.aspx')

@honeypot_route('/_layouts/15/spinstall.aspx', methods=['GET', 'POST'])
def spinstall_15():
    return log_and_respond('/_layouts/15/spinstall.aspx')

@honeypot_route('/_layouts/15/spinstall1.aspx', methods=['GET', 'POST'])
def spinstall1_15():
    return log_and_respond('/_layouts/15/spinstall1.aspx')

@honeypot_route('/_layouts/15/info3.aspx', methods=['GET', 'POST'])
def info3_15():
    return log_and_respond('/_layouts/15/info3.aspx')

@honeypot_route('/_layouts/15/xxx.aspx', methods=['GET', 'POST'])
def xxx_15():
    return log_and_respond('/_layouts/15/xxx.aspx')

# Final catch-all
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_all(path):
    return log_and_respond('/' + path)

if __name__ == '__main__':
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=443, ssl_context=context) 