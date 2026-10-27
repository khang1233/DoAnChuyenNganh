rule AutoCTI_Live_Malware_Indicator {
    meta:
        description = "Auto-generated YARA rule for Anthropic Expands Claude Access for Vetted Cyber Teams as Glasswing Finds 129,000 Flaws [CVE-2020-29583]"
        author = "Autonomous CTI AI Agent"
        sha256_indicator = "00560eaec8e7b1700da1e1747c09cf35222ed881df33864338a3da6efaddeafa"
        severity = "Critical"
    strings:
        $c2_indicator = "34.140.212.230" ascii wide
        $ps_encoded = "powershell.exe -enc" ascii wide nocase
    condition:
        any of them
}