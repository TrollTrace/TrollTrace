# Splunk Security Event Detection Query
<h3>Overview</h3>

This query is designed to detect security-related events from various sources and platforms. It combines multiple conditions to identify potential security threats and returns a summary of the detected events.

```
index="main"
(host="RISK-ANALYST1" OR host="ACCOUNTING1" OR host="ACCOUNTING2" OR host="CFO-LAPTOP" OR host="ip-10-0-0-175" OR host="linsecurity") AND
(sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Security" OR sourcetype="linux_secure" OR sourcetype="apache_error") AND
(
    (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" AND "Process Create" AND (CommandLine="*powershell.exe*" OR CommandLine="*cmd.exe /c*"))
    OR
    (sourcetype="WinEventLog:Security" AND (EventCode=4625 OR EventCode=4740))
    OR
    (sourcetype="linux_secure" AND "Failed password" AND NOT user="known_good_user")
    OR
    (sourcetype="apache_error" AND ("client denied by server configuration" OR "File does not exist" OR "script not found or unable to stat"))
)
| eval AttackDetected=if(
    match(_raw, "Process Create|EventCode=4625|EventCode=4740|Failed password|client denied by server configuration|File does not exist|script not found or unable to stat"),
    "Yes",
    "No"
)
| stats count as EventCount by host, AttackDetected, sourcetype
| sort - EventCount
```
<h3>Index and Host Specification</h3>

```
index="main" (host="RISK-ANALYST1" OR host="ACCOUNTING1" OR host="ACCOUNTING2" OR host="CFO-LAPTOP" OR host="ip-10-0-0-175" OR host="linsecurity")
```
* ***index="main"***: This specifies the index that Splunk should search for events. In this case, it's the "main" index.

* ***(host="RISK-ANALYST1" OR host="ACCOUNTING1" OR host="ACCOUNTING2" OR host="CFO-LAPTOP" OR host="ip-10-0-0-175" OR host="linsecurity")***

  This part of the query filters events by the host field. It looks for events from the following hosts:
  * RISK-ANALYST1
  * ACCOUNTING1
  * ACCOUNTING2
  * CFO-LAPTOP
  * ip-10-0-0-175 (an IP address)
  * linsecurity (a hostname or a machine name)
    
By specifying these hosts, the query will only consider events from these specific hosts. This helps to narrow down the search results and focus on events from specific machines or networks.

<h3>Sourcetype Filtering</h3>

```
(sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Security" OR sourcetype="linux_secure" OR sourcetype="apache_error")
```

* ***(sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"***: This filters events by sourcetype, which is a way to categorize events in Splunk. In this case, it looks for events from the ***"WinEventLog:Microsoft-Windows-Sysmon/Operational"*** sourcetype. This sourcetype is used for Windows event logs related to Sysmon, which is a Windows monitoring tool.
* ***OR***: The "OR" operator is used to combine multiple conditions. It means that if any of the conditions after it are true, the entire condition will be true.
* ***sourcetype="WinEventLog:Security"***: This filters events by another sourcetype, "WinEventLog:Security", which is used for Windows event logs related to security.
* ***OR***: Another "OR" operator to combine conditions.
* ***sourcetype="linux_secure"***: This filters events by another sourcetype, "linux_secure", which is used for Linux security event logs.
* ***OR***: Another "OR" operator to combine conditions.
* ***sourcetype="apache_error"***: This filters events by another sourcetype, "apache_error", which is used for Apache error logs.
  
By using these sourcetypes, the query will only consider events from specific sources, such as Windows event logs, Linux security event logs, and Apache error logs.

<h3>Event Filtering</h3>

The next part of the query uses conditional statements to filter events based on specific criteria.

```
(sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" AND "Process Create" AND (CommandLine="*powershell.exe*" OR CommandLine="*cmd.exe /c*))
```
* This filters WinEventLog:Microsoft-Windows-Sysmon/Operational events where the event is a "Process Create" event.
* It also checks if the command line contains either "powershell.exe*" or "cmd.exe /c", which means it's looking for PowerShell or cmd.exe commands.
* ***(sourcetype="WinEventLog:Security" AND (EventCode=4625 OR EventCode=4740))***
  * This filters WinEventLog:Security events with Event IDs 4625 (logon failure) or 4740 (logon attempt).
* ***(sourcetype="linux_secure" AND "Failed password" AND NOT user="known_good_user")***
  * This filters Linux security event logs where the event contains the phrase "Failed password".
  * It also excludes events from known good users by checking if the user field does not match a list of known good users.
* ***(sourcetype="apache_error" AND ("client denied by server configuration" OR "File does not exist" OR "script not found or unable to stat"))***
  * This filters Apache error logs with specific error messages:
  * "client denied by server configuration"
  * "File does not exist"
  * "script not found or unable to stat"
    
These conditions filter out specific types of events that may indicate security threats.

<h3>Evaluation</h3>

```
eval AttackDetected=if(match(_raw, "Process Create|EventCode=4625|EventCode=4740|Failed password|client denied by server configuration|File does not exist|script not found or unable to stat"), "Yes", "No")
```

* ***eval***: This command evaluates an expression and assigns it to a new field.
* ***AttackDetected***: The new field being created is named "AttackDetected".
* ***if***: The expression is evaluated using an IF statement.
* ***match(_raw, ...)***: The _raw field contains the raw text of the event. The match function checks if any of the specified strings are present in the _raw field.
* ***"Yes" or "No"***: If the condition is true, the value is set to "Yes"; otherwise, it's set to "No".
  
This part of the query evaluates whether an attack has been detected based on specific keywords in the _raw field. If any of these keywords are found, the value of AttackDetected is set to "Yes"; otherwise, it's set to "No"`.

<h3>Statistics and Sorting</h3>

```
stats count as EventCount by host, AttackDetected, sourcetype | sort - EventCount
```

* ***stats count as EventCount***: This command calculates a count of events for each group of results and assigns it to a new field named EventCount.
* ***by host, AttackDetected, sourcetype***: The count is calculated for each combination of host, AttackDetected, and sourcetype.
* ***sort - EventCount***: The results are sorted in descending order by EventCount.
  
This part of the query provides a summary of detected attacks by grouping them by host, attack detection status (yes/no), and sourcetype. The results are sorted in descending order by count to show the most frequent attacks first.

<h3>Place Holders</h3>
Ran these queries nothing came up, leaving them as a place holder :)

```
index=* sourcetype=firewall*
| stats dc(dest_port) as num_dest_port dc(dest_ip) as num_dest_ip by src_ip
| where num_dest_port >500 OR num_dest_ip>500
```

```
1. Detecting Anomalous Network Traffic

index=* (dest_port=22 OR dest_port=80 OR dest_port=443) AND bytes>100000 AND NOT (src_ip=10.0.0.0/24 OR dest_ip=10.0.0.0/24)
  * This query detects unusual network traffic within your internal network, focusing on large file transfers.

index=* (bytes>100000 AND NOT (src_ip=10.0.0.0/24 OR dest_ip=10.0.0.0/24)) AND protocol=http OR protocol=https
  * This query detects unusual HTTP or HTTPS traffic within your internal network.

2. Detecting Malware and Ransomware

index=* (sourcetype=win_eventlog AND EventCode=4625) AND NOT user=" Administrator" AND NOT user="System"
  * This query detects login attempts from unknown users.
index=* (sourcetype=win_eventlog AND EventCode=7045) AND NOT user=" System" AND NOT user="NT AUTHORITY\SYSTEM"
  * This query detects process creation events from unknown users.
index=* (sourcetype=linux_secure AND message contains("malware" OR "ransomware"))
  * This query detects Linux security event logs containing malware or ransomware-related keywords.

3. Detecting Brute Force Attacks

index=* (sourcetype=win_eventlog AND EventCode=4624) AND authentication_type="Kerberos" AND failure_count>10
  * This query detects Kerberos authentication failures with a high failure count, indicating a brute force attack.
index=* (sourcetype=linux_secure AND message contains("failed password"))
  * This query detects Linux security event logs containing failed password attempts.

4. Detecting Data Exfiltration

index=* (sourcetype=win_eventlog AND EventCode=4648) AND object_name="C:\\Windows\\System32"
  * This query detects file accesses to sensitive areas of the Windows system directory.
index=* (sourcetype=linux_secure AND message contains("scp" OR "sftp"))
  * This query detects Linux security event logs containing SCP or SFTP activity, which may indicate data exfiltration.

5. Detecting Lateral Movement

index=* (sourcetype=win_eventlog AND EventCode=4688) AND process_name="cmd.exe" OR process_name="powershell.exe"
  * This query detects command-line execution events from unknown users.
index=* (sourcetype=linux_secure AND message contains("bash" OR "sh"))
  * This query detects Linux security event logs containing bash or sh commands, which may indicate lateral movement.

6. Detecting Command and Control

index=* (sourcetype=win_eventlog AND EventCode=4689) AND process_name="svchost.exe" OR process_name="powershell.exe"
  * This query detects suspicious svchost.exe or powershell.exe processes.
index=* (sourcetype=linux_secure AND message contains("curl" OR "wget"))
  *This query detects Linux security event logs containing curl or wget commands, which may indicate command and control activity.
These queries should help you detect potential security threats within your internal network, focusing on private IP addresses and internal traffic patterns.

1. Detecting PSExec Execution

index=* (sourcetype=win_eventlog AND EventCode=4688) AND process_name="psexec.exe" OR process_name="psexec32.exe"
  * This query detects the execution of psexec.exe or psexec32.exe, which are the common names for the PSExec tool.
index=* (sourcetype=win_eventlog AND EventCode=4689) AND command_line contains("psexec")
  * This query detects commands containing "psexec" in the command line, which may indicate PSExec usage.

2. Detecting Lateral Movement via PSExec

index=* (sourcetype=win_eventlog AND EventCode=4688) AND process_name="psexec.exe" OR process_name="psexec32.exe" AND NOT user="System" AND NOT user="NT AUTHORITY\SYSTEM"
  * This query detects psexec.exe or psexec32.exe executions by unknown users, indicating potential lateral movement.
index=* (sourcetype=win_eventlog AND EventCode=4689) AND command_line contains("psexec") AND NOT user="System" AND NOT user="NT AUTHORITY\SYSTEM"
  * This query detects commands containing "psexec" in the command line, executed by unknown users, which may indicate lateral movement.

3. Detecting Data Exfiltration via PSExec

index=* (sourcetype=win_eventlog AND EventCode=4648) AND object_name="C:\\Windows\\System32" AND process_name="psexec.exe" OR process_name="psexec32.exe"
  * This query detects file accesses to sensitive areas of the Windows system directory when psexec.exe or psexec32.exe is involved.
index=* (sourcetype=win_eventlog AND EventCode=4648) AND object_name="C:\\Windows\\System32" AND command_line contains("psexec")
  * This query detects file accesses to sensitive areas of the Windows system directory when a command containing "psexec" is involved.

4. Detecting Command and Control via PSExec

index=* (sourcetype=win_eventlog AND EventCode=4688) AND process_name="psexec.exe" OR process_name="psexec32.exe" AND command_line contains("curl" OR "wget")
  * This query detects psexec.exe or psexec32.exe executions with curl or wget commands in the command line, which may indicate command and control activity.
index=* (sourcetype=win_eventlog AND EventCode=4689) AND command_line contains("psexec") AND command_line contains("curl" OR "wget")
  * This query detects commands containing "psexec" and curl or wget commands, which may indicate command and control activity.
```
