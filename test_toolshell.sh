#!/bin/bash

# Base endpoint
BASE_URL="https://localhost"

# Disable self-signed certificate check
CURL="curl -k -s -o /dev/null -w '%{http_code}\n'"

echo "1. POST exploit ToolShell (IOC: ToolPane, Referer, params, UA)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" \
  -X POST \
  -H "Referer: /_layouts/SignOut.aspx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
  --data '<exploit>'

echo "2. GET to webshell endpoint (IOC: Webshell probe)"
$CURL "$BASE_URL/_layouts/15/spinstall0.aspx"

echo "3. Generic POST (no IOC)"
$CURL "$BASE_URL/any/endpoint" -X POST --data 'test'

echo "4. GET favicon (no IOC)"
$CURL "$BASE_URL/favicon.ico"

echo "5. POST with ViewState (IOC: ViewState payload)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST --data '__VIEWSTATE=malicious'

echo "6. POST ToolPane v16 (IOC: ToolPane exploit endpoint)"
$CURL "$BASE_URL/_layouts/16/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" -X POST --data '<exploit>'

echo "7. GET info3.aspx (IOC: Webshell probe)"
$CURL "$BASE_URL/_layouts/15/info3.aspx"

echo "8. POST with full Referer (IOC: Referer SignOut.aspx)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST -H "Referer: https://localhost/_layouts/SignOut.aspx" --data '<exploit>'

echo "9. POST with only DisplayMode param (IOC: DisplayMode=Edit)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx?DisplayMode=Edit" -X POST --data '<exploit>'

echo "10. POST with only a= param (IOC: a=/ToolPane.aspx)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx?a=/ToolPane.aspx" -X POST --data '<exploit>'

echo "11. GET root (no IOC)"
$CURL "$BASE_URL/"

echo "12. GET spinstall1.aspx (IOC: Webshell probe)"
$CURL "$BASE_URL/_layouts/15/spinstall1.aspx"

echo "13. GET xxx.aspx (IOC: Webshell probe)"
$CURL "$BASE_URL/_layouts/15/xxx.aspx"