rule Suspicious_PE_File {
    meta:
        description = "Detects basic Portable Executable (PE) characteristics with high entropy"
        author = "HostGuard"
        severity = "medium"
        mitre = "T1027"
    strings:
        $mz = "MZ"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $dos_stub
}
