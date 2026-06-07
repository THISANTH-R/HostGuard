rule Suspicious_Webshell {
    meta:
        description = "Detects common webshell patterns"
        author = "HostGuard"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $php1 = "eval($_POST" ascii nocase
        $php2 = "system($_GET" ascii nocase
        $php3 = "shell_exec(" ascii nocase
        $aspx1 = "<%@ Page Language=\"C#\"" ascii nocase
        $aspx2 = "Process.Start(" ascii nocase
    condition:
        any of them
}
