# Host: Accounting 1 Event Log Analysis

### Query Used: 
```
(index="main" host="ACCOUNTING1" (EventCode=4624 OR EventCode=4672 OR EventCode=4688))
```
The query used is searching for security-related events on the host "ACCOUNTING1" in the "main" index. The query is looking for events with one of three EventCodes:
* 4624: Windows login event (user logged in or out)
* 4672: Windows account lockout event (account locked out due to incorrect login attempts)
* 4688: Windows process creation event (new process started)
  
![Screenshot 2024-07-03 134938.png](https://github.com/TrollTrace/TrollTrace/blob/dc4d6e9470ef4695c9fc1f345376516f4936a6c6/Screenshot%202024-07-03%20134938.png)

![Screenshot 2024-07-03 135141.png](https://github.com/TrollTrace/TrollTrace/blob/dc4d6e9470ef4695c9fc1f345376516f4936a6c6/Screenshot%202024-07-03%20135141.png)

The query returns events that match any of these three EventCodes, showing a table with columns including date, time, event description, message, index, and host. The screenshot appears to show multiple events that match the query criteria, including login events, account lockout events, and process creation events. You can also check out the Full CSV file for this [here](https://github.com/TrollTrace/TrollTrace/blob/f631e39e8dd21504a5c3731e7cd1cef5696d5c7f/Documents/Splunk_CSV_Files/ACCOUNTING_1.csv).

## Event Codes
### 4624: Windows Login Event
Query Used:
```
(index="main" host="ACCOUNTING 1" (EventCode=4624 OR EventCode=4672 OR EventCode=4688)) EventCode=4624
```
![Screenshot 2024-07-03 135332.png](https://github.com/TrollTrace/TrollTrace/blob/dc4d6e9470ef4695c9fc1f345376516f4936a6c6/Screenshot%202024-07-03%20135332.png)

* Event Type: Successful logon (4624)
* Subject: Anonymous account with no specific user or domain information
* Logon Type: Remote network logon from a workstation named "nmap"
* New Logon:
  * Security ID: ANONYMOUS LOGON
  * Account Name: ANONYMOUS LOGON
  * Account Domain: NT AUTHORITY
  * Logon ID: 0x5c94d3d
* Process Information: No specific process name associated with this logon
* Network Information:
  * Workstation Name: nmap
  * Source Network Address: 10.0.0.176
  * Source Port: 44544
* Detailed Authentication Information:
  * Logon Process: NtLmSsp
  * Authentication Package: NTLM
  * Transited Services: empty
  * Package Name (NTLM only): NTLM V1
  * Key Length: 128
  
The event indicates a successful anonymous login from a remote workstation (nmap) to the system ACCOUNTING1 using NTLM authentication. You can view the full CSV file for Event Code 4624 [here](https://github.com/TrollTrace/TrollTrace/blob/b0e84f96459ae930db012cf784e71cd06976d17d/Documents/Splunk_CSV_Files/ACCOUNTING1_4624.csv).

### 4672: Windows Account Lockout Event
Query Used:
```
(index="main" host="ACCOUNTING1" (EventCode=4624 OR EventCode=4672 OR EventCode=4688)) EventCode=4672
```
![Screenshot 2024-07-03 135440.png](https://github.com/TrollTrace/TrollTrace/blob/dc4d6e9470ef4695c9fc1f345376516f4936a6c6/Screenshot%202024-07-03%20135440.png)

* Event Type: Special privilege assignment
* The SYSTEM account has been granted several system-level privileges, including:
  * SeAssignPrimaryTokenPrivilege: Assigning primary tokens
  * SeTcbPrivilege: Accessing TCB (Trusted Computing Base) data
  * SeSecurityPrivilege: Performing security-related actions
  * SeTakeOwnershipPrivilege: Taking ownership of files and folders
  * SeLoadDriverPrivilege: Loading drivers
  * SeBackupPrivilege: Backing up files
  * SeRestorePrivilege: Restoring files
  * SeDebugPrivilege: Debugging processes
  * SeAuditPrivilege: Auditing processes
  * SeSystemEnvironmentPrivilege: Impersonating other users
  
These privileges allow the SYSTEM account to perform various system-level operations. You can view the full-text file for Event Code 4672 [here](/Documents/Splunk_CSV_Files/RiskAnalyst4672.txt).
