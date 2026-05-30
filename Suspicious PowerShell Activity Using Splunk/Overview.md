🔍 Detection Engineering Lab – Suspicious PowerShell Execution

Today I created a Splunk detection to identify potentially malicious PowerShell activity.

Detection focused on:
• EncodedCommand usage
• IEX (Invoke-Expression)
• DownloadString execution

SPL Query:
index=main powershell.exe
| search "EncodedCommand" OR "DownloadString" OR "IEX"
| table _time User ParentProcessName CommandLine

Why it matters:
Attackers frequently abuse PowerShell to execute obfuscated commands, download payloads, and evade traditional defenses.

Investigation points:
• Parent-child process relationship
• User context
• Command-line arguments
• External download indicators

MITRE ATT&CK:
T1059.001 – PowerShell

Building hands-on Detection Engineering skills through Splunk lab exercises and attack simulation datasets.
