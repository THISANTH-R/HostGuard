rule Credential_Dumping_Tools {
    meta:
        description = "Detects Mimikatz and similar credential dumping tools"
        author = "HostGuard"
        severity = "critical"
        mitre = "T1003"
    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "sekurlsa::logonpasswords" ascii wide nocase
        $mimi3 = "lsadump::sam" ascii wide nocase
        $procdump = "procdump" ascii wide nocase
        $lazagne = "lazagne" ascii wide nocase
    condition:
        any of them
}
