# Incident Report: UAC Bypass (UACMe method 34) on MSEDGEWIN10

**Analyst:** Jay Patel
**Data source:** Public EVTX-ATTACK-SAMPLES dataset, analysed with Hayabusa
**Log file analysed:** Privilege Escalation/Sysmon_UACME_34.evtx
**Note:** This is a simulated attack from a public dataset, used to practise incident analysis.

## 1. Summary
On host MSEDGEWIN10, the user IEUser ran UACME.exe from the Desktop with argument 34, a known technique for bypassing Windows User Account Control. Within about 1.2 seconds the tool modified a registry environment variable, triggered the built-in SilentCleanup scheduled task, and obtained a command prompt running at High integrity without any user prompt. Four high-severity alerts fired, three of which independently map to MITRE T1548.002. The risk is high because the attacker gains administrator-level execution silently, which enables further attacks such as credential dumping or persistence.

## 2. Timeline
| Time (UTC) | Detection | Severity | MITRE |
|------------|-----------|----------|-------|
| 2019-08-03 09:46:48.209 | HackTool - UACMe Akagi Execution | high | T1548.002 |
| 2019-08-03 09:46:48.726 | Bypass UAC Using SilentCleanup Task | high | T1548.002 |
| 2019-08-03 09:46:48.924 | Proc Exec (Sysmon Alert): schtasks.exe /run on SilentCleanup | high | none tagged |
| 2019-08-03 09:46:49.402 | UAC Bypass Using Disk Cleanup | high | T1548.002 |

**How the attack worked:**
1. UACME.exe (Medium integrity) writes `C:\Windows\system32\cmd.exe` into the user's `windir` environment variable in the registry.
2. It then runs the SilentCleanup task with `schtasks.exe`. This built-in task runs with elevated rights and trusts `%windir%`.
3. The task expands `%windir%` to the attacker's value, so Task Scheduler launches `cmd.exe` at High integrity. UAC never prompts.

## 3. Affected systems
- Computer: MSEDGEWIN10
- User account: MSEDGEWIN10\IEUser
- Processes: UACME.exe (PID 924) spawned from cmd.exe; schtasks.exe (PID 1268); elevated cmd.exe (PID 1380) spawned by svchost.exe (Task Scheduler)

## 4. MITRE ATT&CK mapping
| Technique | Name | Stage |
|-----------|------|-------|
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Privilege Escalation, Defense Evasion |
| T1053.005 | Scheduled Task/Job: Scheduled Task (supporting; my mapping, not tagged by the rule) | Execution |

## 5. Indicators of compromise
- **Tool:** `C:\Users\IEUser\Desktop\UACME.exe`, version 3.1.9.1905, company field "Hazardous Environments"
- **SHA256:** D76815CE3F4B9FE7A611D6F536F65AF313E2AB2F8BB52EF0998487D89A6E7378
- **MD5:** D57E778DF10F801F47119A04BE990FFD
- **Command lines:** `UACME.exe 34` and `"C:\Windows\System32\schtasks.exe" /run /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup" /i`
- **Registry:** `HKU\S-1-5-21-3461203602-4096304019-2269080069-1000\Environment\windir` set to `"C:\Windows\system32\cmd.exe"`
- **Scheduled task abused:** `\Microsoft\Windows\DiskCleanup\SilentCleanup`
- **Resulting process:** cmd.exe at High integrity with parent `svchost.exe -k netsvcs -p -s Schedule`, and the malformed command line `"C:\Windows\system32\cmd.exe"\system32\cleanmgr.exe /autoclean /d C:`
- **Caveat:** in the registry alert, the Image field shows `explorer.exe`, but the ProcessId (924) and ProcessGuid match UACME.exe. I attribute the write to UACME.exe; this should be verified in the raw Sysmon event.

## 6. Recommendations
**Immediate:** isolate the machine, review what ran in the elevated cmd.exe session, check for new accounts, services or scheduled tasks, and reset the IEUser password.
**Prevention:** set UAC to "Always notify", remove local administrator rights from standard users, and use application control to block unknown tools such as UACME.
**Detection:** alert on writes to `HKCU\Environment\windir`, on `schtasks.exe /run` targeting SilentCleanup, and on High-integrity cmd.exe launched by the Task Scheduler service. Forward Sysmon logs to a central SIEM.

## 7. Lessons learned
Three different rules flagged the same technique (T1548.002), which gives strong confidence this was a real bypass and not a false positive. The Sysmon alert had no MITRE tag, so it would need enrichment before an analyst could place it in the attack chain. Looking at the alerts in time order told the story far better than any single alert. I filtered 5,388 total alerts down to the critical and high ones to find this incident, which shows why severity filtering matters.
