# My Custom Detection Rules

Tested against the public EVTX-ATTACK-SAMPLES dataset using Hayabusa.

| Rule | Event ID | MITRE | Fired? | Hits |
|------|----------|-------|--------|------|
| Security Event Log Cleared | 1102 | T1070.001 | Yes | 24 |
| Whoami Reconnaissance Command | Sysmon 1 | T1033 | Yes | 22 |
| New Service Installed | 7045 | T1543.003 | Yes | 4 |
| User Added To Local Administrators Group | 4732 | T1098 | Yes | 2 |
| Failed Logon Attempt | 4625 | T1110 | Yes | 1 |

Note: the failed logon rule is low severity on purpose. One failed logon is normal, and the alert only becomes meaningful when many occur in a short time.
