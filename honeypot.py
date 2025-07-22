import os
import uuid
import json
import zipfile
from datetime import datetime, date
from flask import Flask, request, make_response
from functools import wraps

app = Flask(__name__)
DATA_DIR = os.environ.get('DATA_DIR', './data')
IIS_HEADER = 'Microsoft-IIS/10.0'
ACCESS_LOG = os.path.join(DATA_DIR, 'access.log')

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
    # Salva body POST
    if body:
        bin_path = os.path.join(DATA_DIR, f'{req_id}-body.bin')
        with open(bin_path, 'wb') as f:
            f.write(body)
        log['body_file'] = os.path.basename(bin_path)
        # Aggiorna ZIP giornaliero
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

# Decorator per endpoint sensibili

def honeypot_route(rule, **options):
    def decorator(f):
        @app.route(rule, **options)
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Endpoint dedicati
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

# Catch-all finale
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_all(path):
    return log_and_respond('/' + path)

if __name__ == '__main__':
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=443, ssl_context=context) 