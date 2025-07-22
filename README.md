# ToolShell-Honeypot (SharePoint Zero-Day)

A Docker-based honeypot simulating a Microsoft IIS server vulnerable to the ToolShell/SharePoint zero-day.

## Main Features
- Accepts and logs all HTTP requests (GET, POST, ...)
- Emulates IIS headers
- Logs requests in JSON, POST bodies in .bin, and daily ZIP archives
- HTTPS with self-signed certificate
- Streamlit dashboard for data visualization and download
- **Realistic endpoints**: catch-all + dedicated routes for endpoints used in ToolShell/SharePoint campaigns
- **IOC detection**: automatic tagging of suspicious requests based on threat intelligence indicators
- **Apache/Nginx-style access.log**: SIEM-compatible log file
- **Visual alert**: stdout alert for IOC detection
- **Daily ZIP/log rotation**: daily archives of POST bodies

## Architecture

```
Docker Compose
├── honeypot (Flask, port 443, /data)
└── dashboard (Streamlit, port 8501, /data)
```

## Monitored Endpoints and Patterns

The server emulates and logs in detail:
- `/` (catch-all)
- `/favicon.ico`
- `/_layouts/SignOut.aspx`
- `/_layouts/15/ToolPane.aspx` and `/_layouts/16/ToolPane.aspx` (POST/GET, parameters DisplayMode=Edit, a=/ToolPane.aspx)
- `/_layouts/15/spinstall0.aspx`, `/_layouts/16/spinstall0.aspx`, `spinstall.aspx`, `spinstall1.aspx`, `info3.aspx`, `xxx.aspx`

**Indicators of Compromise (IOC) detected and tagged in logs:**
- POST to ToolPane.aspx with exploit parameters
- Header Referer: `/_layouts/SignOut.aspx` (or variants with host)
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0`
- Probing GET/POST to known webshell endpoints
- Presence of ViewState payload in POST

Each request is logged in JSON, and if suspicious, is marked with the `ioc` field (array of detected indicators).

## Logging and Data Collection
- **JSON**: one file per request, with header, path, args, body_file, IOC
- **.bin**: POST bodies
- **ZIP**: daily archive of all POST bodies
- **access.log**: Apache/Nginx-style log, one line per request, with IOC
- **Visual alert**: stdout alert for IOC detection

## Quick Start

1. Generate a self-signed certificate:
   ```bash
   openssl req -x509 -nodes -days 365 \
     -newkey rsa:2048 -keyout key.pem -out cert.pem \
     -subj "/CN=sharepoint.local"
   cp cert.pem key.pem ToolShell-Honeypot/
   ```
2. Build and start:
   ```bash
   cd ToolShell-Honeypot
   docker-compose build
   docker-compose up
   ```
3. Test the honeypot:
   ```bash
   curl -k "https://localhost/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" -X POST \
     -H "Referer: /_layouts/SignOut.aspx" --data '<exploit>'
   ```
4. Access the dashboard:
   - http://localhost:8501

## Notes
- Data is saved in ./data
- ZIP archives are rotated daily (YYYY-MM-DD.zip)
- Dashboard and honeypot are separated for security
- access.log is SIEM-compatible

## Threat Intelligence Indicators and Sources
- Indicators and patterns implemented based on:
  - [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)
  - SentinelOne, Talos, Sophos, PaloAlto Unit42
- Main IOCs:
  - POST to /ToolPane.aspx with exploit parameters
  - Referer: /_layouts/SignOut.aspx
  - User-Agent: Firefox/120.0
  - Probing on spinstall0.aspx/info3.aspx/xxx.aspx
  - ViewState in body

## TODO
- Webhook alerting, advanced parsing, SIEM integration, dashboard authentication... 