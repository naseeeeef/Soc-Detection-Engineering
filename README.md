# SOC Detection Engineering

A hands-on Detection Engineering and Threat Hunting repository focused on building, testing, and documenting security detections using Splunk.

This project is designed to improve blue-team skills through practical detection development, log analysis, threat hunting, MITRE ATT&CK mapping, and investigation workflows.

---

## Objectives

- Build real-world detection use cases
- Improve SPL (Search Processing Language) skills
- Understand attacker techniques and behaviors
- Map detections to MITRE ATT&CK
- Develop investigation playbooks
- Create a public Detection Engineering portfolio

---

## Tools Used

- Splunk Enterprise
- Sysmon
- Windows Event Logs
- MITRE ATT&CK
- Atomic Red Team
- Sigma Rules
- GitHub

---

## Detection Workflow

1. Upload logs into Splunk
2. Analyze raw events
3. Create SPL detection logic
4. Validate detection results
5. Investigate suspicious activity
6. Map findings to MITRE ATT&CK
7. Document investigation process
8. Publish findings and lessons learned

---

## Detection Use Cases

| Day | Use Case | MITRE ATT&CK |
|------|----------|-------------|
| 1 | Suspicious PowerShell Execution | T1059.001 |
| 2 | Multiple Failed Logins | T1110 |
| 3 | Word Spawning CMD | T1204 |
| 4 | Certutil Download Activity | T1105 |
| 5 | Rundll32 Abuse | T1218 |
| ... | More Use Cases | Ongoing |
| 60 | Full Ransomware Attack Chain | Multiple |

---

## Repository Structure

```text
Soc-Detection-Engineering/
│
├── detections/
│   ├── powershell/
│   ├── brute-force/
│   ├── ransomware/
│   ├── persistence/
│   └── lateral-movement/
│
├── sigma-rules/
│
├── threat-hunting/
│
├── investigation-guides/
│
├── screenshots/
│
├── datasets/
│
└── README.md
```

---

## Detection Template

Each detection contains:

- Threat Overview
- Sample Logs
- SPL Query
- Detection Logic
- Investigation Steps
- False Positive Analysis
- MITRE ATT&CK Mapping
- Tuning Recommendations
- References

---

## Example Detection

### Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001

**Detection Logic**

```spl
index=main powershell.exe
| search "EncodedCommand" OR "DownloadString" OR "IEX"
| table _time User ParentProcessName CommandLine
```

**Investigation Focus**

- Encoded commands
- PowerShell download cradles
- Parent-child process relationships
- External connections
- User context

---

## Skills Developed

- Detection Engineering
- Threat Hunting
- SPL Development
- Log Analysis
- SOC Investigations
- MITRE ATT&CK Mapping
- Detection Tuning
- Incident Analysis

---

## Disclaimer

All detections, logs, and attack simulations are performed in controlled lab environments for educational and research purposes only.

---

## Author

Naseef

SOC Analyst | Detection Engineering Learner | Splunk | Threat Hunting | Cybersecurity
