rule ToolShell_ViewState_Exploit
{
    meta:
        description = "Detects ToolShell exploit using __VIEWSTATE and ysoserial"
    strings:
        $viewstate = "__VIEWSTATE"
        $ysoserial = "ysoserial"
    condition:
        $viewstate and $ysoserial
}

rule Webshell_ASPX_Generic
{
    meta:
        description = "Detects generic ASPX webshell patterns"
    strings:
        $aspx = "<%@ Page Language="
        $eval = "eval(Request.Item"
        $cmd = "System.Diagnostics.Process"
        $runtime = "Runtime.getRuntime().exec"
        $godzilla = "Godzilla"
    condition:
        $aspx and (any of ($eval, $cmd, $runtime, $godzilla))
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Detects PowerShell encoded command in payload"
    strings:
        $ps1 = "powershell"
        $enc = "-EncodedCommand"
        $b64 = "FromBase64String"
    condition:
        $ps1 and ($enc or $b64)
}

rule Suspicious_Long_Base64
{
    meta:
        description = "Detects long base64-encoded strings in POST body"
    strings:
        $b64 = /[A-Za-z0-9+\/=]{40,}/
    condition:
        $b64
}

rule Suspicious_NOP_Sled
{
    meta:
        description = "Detects NOP sled (potential shellcode) in binary payload"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule Suspicious_PE_Upload
{
    meta:
        description = "Detects PE file header in uploaded body"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule ToolShell_spinstall0_Webshell
{
    meta:
        description = "Detects spinstall0.aspx webshell drop typical of ToolShell"
    strings:
        $aspx = "<%@ Import Namespace=\"System.Diagnostics\" %>"
        $crypto = "GetApplicationConfig"
        $machinekey = "MachineKeySection"
    condition:
        $aspx and ($crypto or $machinekey)
}

rule Suspicious_PowerShell_Concat
{
    meta:
        description = "Detects PowerShell command concatenation (e.g. 'I'+'EX')"
    strings:
        $iex_concat1 = /("I"\s*\+\s*"EX")/
        $iex_concat2 = /(\'I\'\s*\+\s*\'EX\')/
    condition:
        $iex_concat1 or $iex_concat2
}

rule Suspicious_PowerShell_CharCodes
{
    meta:
        description = "Detects PowerShell char code construction ([char]73+[char]69+[char]88)"
    strings:
        $charcode = /\[char\]\d+\s*\+\s*\[char\]\d+/
    condition:
        $charcode
}

rule Suspicious_PowerShell_VariableIEX
{
    meta:
        description = "Detects PowerShell variable assignment to IEX"
    strings:
        $variex = /\$[a-zA-Z0-9_]+\s*=\s*["']IEX["']/
    condition:
        $variex
}

rule Suspicious_PowerShell_UTF16LE_Base64
{
    meta:
        description = "Detects short base64 likely to be UTF-16LE encoded PowerShell"
    strings:
        $b64utf16 = /[A-Za-z0-9+\/]{8,16}={0,2}/
    condition:
        $b64utf16
}

rule Suspicious_PowerShell_Pipeline
{
    meta:
        description = "Detects PowerShell pipeline usage (IEX (Get-Content ...))"
    strings:
        $iex_pipe = /IEX\s*\(\s*Get-Content/
    condition:
        $iex_pipe
}

rule Suspicious_PowerShell_InvokeObfuscation
{
    meta:
        description = "Detects artifacts of Invoke-Obfuscation (scriptblock, [char], [byte], [string], ::Create)"
    strings:
        $scriptblock = "[scriptblock]::Create"
        $char = "[char]"
        $byte = "[byte]"
        $string = "[string]"
        $create = "::Create"
    condition:
        $scriptblock or $char or $byte or $string or $create
} 