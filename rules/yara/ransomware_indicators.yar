rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware note patterns and shadow copy deletion scripts"
        author = "HostGuard"
        severity = "critical"
        mitre = "T1486"
    strings:
        $note1 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $note2 = "pay the ransom" ascii wide nocase
        $note3 = "decrypt your files" ascii wide nocase
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "wmic shadowcopy delete" ascii nocase
    condition:
        2 of ($note*) or any of ($shadow*)
}
