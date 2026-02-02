# LSASS Cloning Detection Query

## Overview
This KQL query detects suspicious LSASS (Local Security Authority Subsystem Service) process cloning attempts by correlating abnormal LSASS creation events with remote thread injection activities.

## Detection Logic

### Stage 1: Identify Suspicious LSASS Creations
The query identifies LSASS processes created by unexpected parent processes:
- **Normal behavior**: LSASS is spawned by `wininit.exe`
- **Suspicious behavior**: LSASS spawned by any other parent process

**Data Sources:**
- Windows Security Event ID 4688 (Process Creation)
- Sysmon Event ID 1 (Process Creation)

### Stage 2: Correlate with Remote Thread Injection
After identifying suspicious LSASS instances, the query looks for remote thread creation (Sysmon Event ID 8) targeting these LSASS processes within a 5-minute window.

**Correlation Logic:**
- Matches LSASS Process ID with target process of remote thread events
- Ensures thread injection occurs after LSASS creation
- Filters for interactions within 5 minutes of LSASS spawn

## Prerequisites

### Required Data Sources
- Windows Security Events (EventID 4688)
- Sysmon Events (EventID 1, 8)
  - Event ID 1: Process Creation
  - Event ID 8: CreateRemoteThread

### Log Collection Requirements
Ensure the following are enabled:
- Audit Process Creation (Security Event 4688)
- Sysmon process creation logging
- Sysmon remote thread creation logging

## Configuration

### Time Range
Modify the `StartTime` and `EndTime` variables to match your investigation timeframe:

```kql
let StartTime = datetime(2025-10-30, 12:00:00);
let EndTime   = datetime(2025-11-03, 13:00:00);
```

### Detection Window
The query uses a 5-minute correlation window. Adjust if needed:
```kql
| where InteractionTime < (EventCreation + 5m)
```

## Query Output

The query returns the following fields:
- **InitialLsassCreationTime**: When the suspicious LSASS process was created
- **Computer**: Hostname where the activity occurred
- **ParentOfLsass**: The unexpected parent process that spawned LSASS
- **LsassProcessId**: Process ID of the suspicious LSASS instance
- **InteractionTime**: When remote thread injection was detected
- **InteractionSource**: Process that performed the thread injection

## Use Cases

### Credential Theft Detection
LSASS cloning is commonly used in credential dumping attacks. This query helps detect:
- Mimikatz-style credential theft
- Custom credential dumpers
- Living-off-the-land techniques using legitimate tools

### Incident Response
Use this query during investigations of:
- Suspected credential compromise
- Post-exploitation activity
- Advanced persistent threat (APT) campaigns

## MITRE ATT&CK Mapping

- **Tactic**: Credential Access (TA0006)
- **Technique**: OS Credential Dumping (T1003)
- **Sub-technique**: LSASS Memory (T1003.001)

## False Positives

Potential false positives may include:
- Legitimate security tools that interact with LSASS
- System management utilities
- Antivirus/EDR solutions performing process inspection

**Recommendation**: Baseline your environment to identify and exclude known-good processes.

## Performance Considerations

The query uses `materialize()` to optimize the initial LSASS creation lookup. For large environments:
- Narrow the time range when possible
- Consider pre-filtering by Computer if investigating specific hosts
- Monitor query execution time and adjust correlation window as needed

## Example Detection Scenario

```
InitialLsassCreationTime: 2025-11-01 14:23:15
Computer: WORKSTATION-01
ParentOfLsass: powershell.exe
LsassProcessId: 8472
InteractionTime: 2025-11-01 14:23:18
InteractionSource: cmd.exe
```

This indicates PowerShell spawned an LSASS process, followed 3 seconds later by cmd.exe injecting a thread into it - highly suspicious behavior consistent with credential dumping.

## Version History
- **v1.0** - Initial release

## Author
Bryce Maxheimer

## References
- [MITRE ATT&CK - T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
