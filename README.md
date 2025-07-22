# ToolShell-Honeypot (SharePoint Zero-Day)

A Docker-based honeypot simulating a Microsoft IIS server vulnerable to the ToolShell/SharePoint zero-day.

## Main Features
- Accepts and logs all HTTP requests (GET, POST, ...)
- Emulates IIS headers
- Logs requests in JSON, POST bodies in .bin, and daily ZIP archives
- HTTPS with self-signed certificate
- Streamlit dashboard for data visualization and download
- **Realistic endpoints:** catch-all + dedicated routes for endpoints used in ToolShell/SharePoint campaigns
- **IOC detection:** automatic tagging of suspicious requests based on threat intelligence indicators
- **Apache/Nginx-style access.log:** SIEM-compatible log file
- **Visual alert:** stdout alert for IOC detection
- **Daily ZIP/log rotation:** daily archives of POST bodies
- **Dashboard features:** summary table with Time, Method, Path, IP, IOC; IOC filter; request details with safe body preview (hex and text); global downloads for all .bin, all JSON logs, and access.log

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

## Indicators of Compromise (IOC) Detected

Each request is analyzed for the following IOCs (Indicators of Compromise):

- **ToolPane exploit endpoint:** Requests to `/ToolPane.aspx` endpoints, especially with suspicious parameters.
- **DisplayMode=Edit:** Presence of the `DisplayMode=Edit` parameter in the query string.
- **a=/ToolPane.aspx:** Presence of the `a=/ToolPane.aspx` parameter in the query string.
- **Referer SignOut.aspx:** Requests with the `Referer` header set to `/layouts/SignOut.aspx` or its variants.
- **Suspicious User-Agent:** Requests with User-Agent strings known from real-world attacks (e.g., Firefox/120.0).
- **Webshell probe:** Requests to known webshell endpoints (`spinstall0.aspx`, `spinstall.aspx`, `spinstall1.aspx`, `info3.aspx`, `xxx.aspx`).
- **ViewState payload:** POST requests containing `__VIEWSTATE` in the body.

**All detected IOCs are shown as badges in the dashboard and can be used to filter requests.**

## Data Collected and Displayed

- **Summary Table:** Shows Time, Method, Path, IP, and IOC for each request.
- **Request Details:** For each request, you can view:
  - All HTTP headers
  - Query parameters
  - Remote IP address
  - IOC badges
  - Body preview (hex for all, and as text if Content-Type is textual)
  - Download buttons for body and JSON log
- **Global Downloads:** Download all POST bodies (.bin) as a daily ZIP, all JSON logs as a ZIP, and the full access.log.
- **Access Log:** Apache/Nginx-style log, one line per request, with IOC information.

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
   # Run the basic endpoint test script
   ./test_toolshell.sh

   # Run the body content test script (covers text, JSON, XML, form, binary, and IOC cases)
   ./test_toolshell_bodies.sh
   ```
   These scripts will send a variety of requests to the honeypot, simulating real-world attack and probe scenarios. After running them, check the dashboard at http://localhost:8501 to review the results, IOC detection, and data previews.

## Notes
- Data is saved in ./data
- ZIP archives are rotated daily (YYYY-MM-DD.zip)
- Dashboard and honeypot are separated for security
- access.log is SIEM-compatible

## Threat Intelligence and Detection Logic

The IOC patterns and detection logic are based on real-world attack campaigns and public threat intelligence for ToolShell/SharePoint vulnerabilities, including:
- Exploit attempts on ToolPane.aspx endpoints with specific parameters
- Use of known malicious Referer and User-Agent headers
- Probing of webshell endpoints
- Detection of ViewState payloads in POST bodies

## TODO
- Webhook alerting, advanced parsing, SIEM integration, dashboard authentication... 