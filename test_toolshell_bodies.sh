#!/bin/bash

BASE_URL="https://localhost"
CURL="curl -k -s -o /dev/null -w '%{http_code}\n'"

echo "1. Plain text body (text/plain)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data 'This is a plain text body.'

echo "2. JSON body (application/json)"
$CURL "$BASE_URL/test/json" -X POST -H "Content-Type: application/json" --data '{"key": "value", "test": true}'

echo "3. XML body (application/xml)"
$CURL "$BASE_URL/test/xml" -X POST -H "Content-Type: application/xml" --data '<root><item>value</item></root>'

echo "4. Form-encoded body (application/x-www-form-urlencoded)"
$CURL "$BASE_URL/test/form" -X POST -H "Content-Type: application/x-www-form-urlencoded" --data 'username=admin&password=secret'

echo "5. Binary body (application/octet-stream)"
# Generate 32 random bytes and send as binary
dd if=/dev/urandom bs=32 count=1 2>/dev/null | $CURL "$BASE_URL/test/binary" -X POST -H "Content-Type: application/octet-stream" --data-binary @-

echo "6. ViewState payload (text, triggers IOC)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST -H "Content-Type: text/plain" --data '__VIEWSTATE=malicious'

echo "7. JSON body to ToolPane exploit (triggers IOC + text preview)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" \
  -X POST \
  -H "Referer: /_layouts/SignOut.aspx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
  -H "Content-Type: application/json" \
  --data '{"exploit": "true", "payload": "test"}'

echo "8. Binary body to ToolPane exploit (triggers IOC, binary preview only)"
dd if=/dev/urandom bs=32 count=1 2>/dev/null | $CURL "$BASE_URL/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" \
  -X POST \
  -H "Referer: /_layouts/SignOut.aspx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @-