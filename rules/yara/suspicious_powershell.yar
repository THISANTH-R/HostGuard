rule Suspicious_PowerShell_Script {
    meta:
        description = "Detects suspicious PowerShell script patterns"
        author = "HostGuard"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $enc1 = "FromBase64String" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "-encodedcommand" ascii nocase
        $dl1 = "DownloadString" ascii nocase
        $dl2 = "DownloadFile" ascii nocase
        $dl3 = "Invoke-WebRequest" ascii nocase
        $dl4 = "Net.WebClient" ascii nocase
        $exec1 = "Invoke-Expression" ascii nocase
        $exec2 = "IEX" ascii nocase
        $exec3 = "Invoke-Command" ascii nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii nocase
        $bypass2 = "Set-ExecutionPolicy" ascii nocase
        $cred1 = "Get-Credential" ascii nocase
        $cred2 = "ConvertTo-SecureString" ascii nocase
    condition:
        any of ($enc*) or (any of ($dl*) and any of ($exec*)) or any of ($bypass*) or any of ($cred*)
}
