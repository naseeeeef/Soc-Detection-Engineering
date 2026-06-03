Detection Engineering Lab – Word Spawning CMD.exe

Splunk detection to identify suspicious parent-child process relationships where Microsoft Word launches Command Prompt.

Detection focused on:
• WINWORD.EXE spawning cmd.exe
• Macro-based execution attempts
• Suspicious command-line activity
• Potential follow-on PowerShell execution

SPL Query:
index=main
(ParentImage=WINWORD.EXE OR ParentImage=EXCEL.EXE OR ParentImage=POWERPNT.EXE)
(Image=cmd.exe OR Image=powershell.exe OR Image=wscript.exe OR Image=cscript.exe)
| stats count by User ParentImage Image CommandLine

• WINWORD.EXE: Microsoft Word should primarily be used for document processing. In most enterprise environments, it has very few legitimate reasons to launch system-level command interpreters.
• cmd.exe: Command Prompt allows execution of operating system commands. When launched from Word, it may indicate that a macro or malicious document is attempting to execute commands on the host.
• Parent-Child Relationship: Parent-child process monitoring is a powerful behavioral detection technique. Instead of relying on file hashes or signatures, it focuses on how processes interact, making it more resilient against malware variations.
• PowerShell Follow-on Activity: Many malicious Office documents launch cmd.exe first and then execute PowerShell to download payloads, establish persistence, or communicate with command-and-control infrastructure.

Why it matters:
Attackers frequently use malicious Office documents as an initial access vector. Monitoring abnormal parent-child process relationships can help identify macro-based attacks, malware execution, and early stages of compromise before additional payloads are delivered.

Investigation points:
• User who opened the document
• Command-line arguments executed
• PowerShell or script execution activity
• Document source (email, download, shared drive)
• Additional child processes spawned after cmd.exe

Potential False Positives:
- Legitimate administrative scripts launched from Word
- Internal automation using Office macros
- IT testing activities

MITRE ATT&CK:
• T1204 – User Execution
