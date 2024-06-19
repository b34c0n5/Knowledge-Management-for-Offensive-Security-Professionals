## Objective

___
```ad-info
title:Objective 

- This note is used to keep track of the domain's discovery/enumeration, privilege escalation and lateral movement processes (once a foothold is established)
```
___

## Discovery

### Checklist

- [ ] [[Discovery - Users (AD)]]
- [ ] [[Discovery - Groups (AD)]]
- [ ] [[Discovery - Domain Computers (AD)]]
- [ ] [[Discovery - Group Policy Objects + Organizational Units (AD)]]
- [ ] [[Privilege Escalation - ACLs (AD)]]
- [ ] [[Discovery - Domain + Forest (AD)]]
- [ ] [[Forest Trusts (AD)]]
- [ ] [[Discovery - User Hunting (AD)]]
- [ ] Domain Shares
- [ ] Port Scan

### Users

*All users*

```ad-check
title:Users List
~~~powershell
get-aduser -filter * | select SamAccountName, enabled, sid
~~~
*Screenshot*
___

```

*Users with SPNs*

```ad-check
title:SPN Users List
~~~powershell
get-adserviceaccount -filter * | select samaccountname, SID, objectclass, ObjectGuid, distinguishedname, enabled | format-list
~~~
*Screenshot*
___

```

*Users with Administrative Privileges*

```ad-check
title:Admin Users List 
~~~powershell
get-aduser -filter * | ?{$_.samaccountname -match "admin"} | Select-Object samaccountname 
~~~
*Screenshot*
___

```

*Domain Admins Members*

```ad-check
title:Domain Administrator Groups Members List
~~~powershell
get-adgroupmember "Domain Admins" -Recursive
~~~
*Screenshot*
___

```

*Enterprise Admins* (run this on the root forest using -server)

```ad-check
title:Enterprise Administrator Group Members List
~~~powershell
get-adgroupmember "Enterprise Admins" -Recursive
~~~
*Screenshot*
___


```

### Groups

*Names + SID List* (only copy non default ones here. RID >= 1000)

```ad-check
title:Groups List Simple
~~~powershell
get-adgroup -filter * | select name, sid
~~~
*Screenshot*
___

```

*Admin Groups*

```ad-check
title:Administrator Groups List Simple
~~~powershell
get-adgroup -filter 'Name -like "*admin*"' | select Name,sid
~~~
*Screenshot*
___

```

*Get User Memberships* (always check new compromised users).

[From PowerTools.ps1](https://github.com/gustanini/PowershellTools/blob/main/PowerTools.ps1)

```ad-check
title:Check User Memberships
~~~powershell
Get-NestedGroupMembership USER
~~~
*Screenshot*
___

```

### Computers

*All Computers, names, machine account names and SIDs*

```ad-check
title:Computers List Simple
~~~powershell
Get-ADComputer -filter * | select dnshostname, SamAccountName, SID
~~~
*Screenshot*
___

```

*Accessible Computers (ICMP)*

```ad-check
title:ICMP Available Computers List
~~~powershell
get-adcomputer -filter * | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName -erroraction silentlycontinue} | select -expandproperty Address
~~~
*Screenshot*
___


```

*Domain Controllers*

```ad-check
title:Domain Controllers List
~~~powershell
Get-ADDomainController -filter * | select-object ComputerObjectDN, domain, enabled, forest, hostname, ipv4address, isglobalcatalog, ldapport, name, operatingsystem, serverobjectdn
~~~
*Screenshot*
___


```

### GPO

> These GPO Commands use powerview. You can import GPOModule as an alternative.

*List of GPOs*

```ad-check
title:GPOs List Name + GUID
~~~powershell
Get-DomainGPO | select displayname, objectguid
~~~
*Screenshot*
___

```

*GPOs + Location*

```ad-check
title:GPOs + Location
~~~powershell
Get-DomainGPO | select displayname, gpcfilesyspath, distinguishedname, objectguid | fl
~~~
*Screenshot*
___

```

**High Value Targets**

*Restricted Group GPO*

```ad-check
title:Restricted Group via GPO

Identify users or groups granted admin access due to a GPO and display computers under their administrative control.
___
~~~powershell
Get-DomainGPOLocalGroup
~~~
*Screenshot*
___

```

*Admin Access Through GPO 1*

```ad-check
title:Admin Access via GPO

Take domain computers, determine users and groups with admin access on them through GPO (not 100% accurate)
___
~~~powershell
get-domaincomputer | Get-DomainGPOComputerLocalGroupMapping -ErrorAction SilentlyContinue
~~~
*Screenshot*
___

```

*Admin Access Through GPO 2*


```ad-check
title:Admin Access via GPO Location

Take domain users, determine where they have admin access through GPO
___
~~~powershell
Get-Domainuser | Get-DomainGPOUserLocalGroupMapping -ErrorAction SilentlyContinue
~~~
*Screenshot*
___

```

### OU

*OU List + GUIDs*

```ad-check
title:OU + GUID List
~~~powershell
Get-ADOrganizationalUnit -Filter * | Select-Object name, DistinguishedName, ObjectGUID, LinkedGroupPolicyObjects | fl
~~~
*Screenshot*
___

```

*GPOs applied on an OU*

```ad-check
title:GPOs on a OU

This one can be a pain to enumerate individually, rather get all GPOs in one terminal and all OUs in another and correlate
___

*first terminal*

~~~powershell
Get-ADOrganizationalUnit -Filter * | select Name,DistinguishedName,LinkedGroupPolicyObjects | fl
~~~

*second terminal*

~~~powershell
get-domaingpo | select displayname,name | fl
~~~
*Screenshot*
___


```

*List of Computers in a OU* (try without last where object filter, then filter if needed)

```ad-check
title:Computers in Specified OU

Look at the distinguished name, first CN is computer name, first OU is the organizational unit.
___
~~~powershell
Get-ADOrganizationalUnit -filter * | %{Get-ADComputer -filter * -SearchBase $_} | ?{$_.SamAccountName -notmatch "student"}
~~~
*Screenshot*
___


```

**High Value Targets**

*Users/Groups with admin access using all OUs*

```ad-check
title:Users with Admin Access via GPO using OUs
~~~powershell
(Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping -ErrorAction SilentlyContinue
~~~
*Screenshot*
___

```

*List users/groups with admin access using a specific OU*

```ad-check
title:Users with Admin Access via Specified OU

Use OU Distinguished Name
___
~~~powershell
(Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping -ErrorAction SilentlyContinue
~~~
*Screenshot*
___

```

### ACLs 

```ad-info

- *ObjectDN* = target object
- *IdentityReference* = Object that has permissions over target
- *ActiveDirectoryRights* = Rights over target
```

*Compromised Users ACLs*

[From PowerTools.ps1](https://github.com/gustanini/PowershellTools)

```ad-check
title:Interesting ACLs for compromised users 

Run against every new user you compromise and their group memberships (enumerate their nested group memberships).

~~~powershell
Find-ADInterestingACL -Identity "user1|group1"
~~~
*Screenshot*
___

```

*Get Domain Admins' ACLs*

```ad-check
title:Domain Admins Group's ACL

> This command will generate a ton of output and is not really that useful unless used for an attack. (Use Distinguished Name)

~~~powershell
(get-acl "AD:\CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local").access | ?{$_.ActiveDirectoryRights -match 'write'} | select ActiveDirectoryRights, AccessControlType, IdentityReference | ?{$_.IdentityReference -notmatch 'BUILTIN|NT|Exchange'} | fl
~~~
*Screenshot*
___

```

*Get High Value Groups/Users ACLs*

```ad-check
title:Check Target ACLs

> This command will generate a ton of output and is not really that useful unless used for an attack. (Use Distinguished Name)

~~~powershell
(get-acl "AD:\CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local").access | ?{$_.ActiveDirectoryRights -match 'write'} | select ActiveDirectoryRights, AccessControlType, IdentityReference | ?{$_.IdentityReference -notmatch 'BUILTIN|NT|Exchange'} |fl
~~~
*Screenshot*
___

```

### Domains

*Current Domain Information*

```ad-check
title:Current Domain Information
~~~powershell
get-addomain | select Name, InfrastructureMaster, DistinguishedName, domainsid, LinkedGroupPolicyObjects, ChildDomains, ComputersContainer, DomainControllersContainer, Forest, ParentDomain, DNSRoot
~~~
*Screenshot*
___

```

*Passwords Policy* 

~~~ad-check

(powerview)

```powershell
(Get-DomainPolicyData).systemaccess
```
*Screenshot*
___

~~~

*Kerberos Policy*

```ad-check
title:Kerberos Policy

(powerview)

~~~powershell
(Get-DomainPolicy).KerberosPolicy
~~~
*Screenshot*
___

```

### Trusts

*Forest Information*

```ad-check
title:Forest Information
~~~powershell
Get-ADForest
~~~
*Screenshot*
___

```

*Domains in Current Forest*

```ad-check
title:Domains in Current Forest
~~~powershell
(Get-ADForest).domains
~~~
*Screenshot*
___

```

*Global Catalogs*

```ad-check
title:Global Catalogs in Current Forest
~~~powershell
(Get-ADForest).globalcatalogs
~~~
*Screenshot*
___

```

*Current Domain Trusts*

```ad-check
title:Current Domain Trusts List
~~~powershell
Get-ADTrust -Filter *
~~~
*Screenshot*
___

```

*Current Forest Trusts*

```ad-check
title:Current Forest Trusts
~~~powershell
Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
~~~
*Screenshot*
___

```

### User Hunting

First create a list of computers for the current domain

```ad-tip
title:Create List of Computers
~~~powershell
mkdir c:\temp
(Get-ADComputer -Filter *).dnshostname > C:\Temp\Computers.txt
~~~
```

*Domain Admins Sessions*

```ad-check
title:Domain Admin Sessions Location

Check access flag checks if your user has admin access there

~~~powershell
Find-DomainUserLocation [-CheckAccess]
~~~
*Screenshot*
___

```

*Sessions on Commonly Used Servers*

```ad-check
title:Domain Admin Sessions Location Alt
~~~powershell
Find-DomainUserLocation -Stealth
~~~
*Screenshot*
___

```

*Computers where custom Group users have sessions*

```ad-check
title:Group Sessions Location
~~~powershell
Find-DomainUserLocation -UserGroupIdentity "StudentUsers"
~~~
*Screenshot*
___

```

*Find Computers where current user has admin access*

```ad-check
title:Find Admin Access Current User - Powershell Remoting
~~~powershell
. .\Find-PSRemotingLocalAdminAccess.ps1

Find-PSRemotingLocalAdminAccess -ComputerFile C:\Temp\Computers.txt
~~~
*Screenshot*
___

```

```ad-check
title:Find Admin Access Current User - WMI 
~~~powershell
. .\Find-WMILocalAdminAccess

Find-WMILocalAdminAccess -ComputerFile C:\Temp\Computers.txt
~~~
*Screenshot*
___

```

### Shares

*Computer Shares*

```ad-check
title:List All Shares

If -CheckShareAccess is passed, then only shares the current user has read access to are returned

~~~powershell
# powerview
Find-DomainShare [-CheckShareAccess]
~~~

~~~powershell
# ad-module
Get-ADComputer -filter * -properties Name | Select -ExpandProperty Name | % {Get-CIMInstance -Class win32_share -ComputerName $_ -ErrorAction SilentlyContinue}
~~~
*Screenshot*
___

```

### Port Scan

~~~ad-check
It will be faster to perform a port scan from the compromised machine than from out attacker machine since we are connected to the other machines directly.

Use `Invoke-Portscan.ps1` from PowerSploit to perform this discovery.

```
Invoke-Portscan -Hosts web06 -TopPorts 50
```

*Screenshot*

___
~~~

## Privilege Escalation / Lateral Movement

### Checklist

- [ ] Kerberoasting Attacks
	- [ ] [[AD Privilege Escalation - Kerberoasting Attack]]
	- [ ] Targeted Kerberoasting
	 - [ ] [[AD Privilege Escalation - AS-REP Roasting Attack]]
	- [ ] Targeted AS-REP Roasting
- [ ] [[AD Privilege Escalation - LAPS]]
- [ ] [[AD Privilege Escalation - gMSA]]
- [ ] Kerberos Delegation Attacks 
	- [ ] [[AD Privilege Escalation - Kerberos Unconstrained Delegation Attack]], [[Unconstrained Delegation Abuse (AD)]], [[Unconstrained Delegation + Printer Bug + DCSync (AD)]]
	- [ ] [[AD Privilege Escalation - Kerberos Constrained Delegation Attack]], [[Constrained Delegation Abuse (AD)]]
	- [ ] [[AD Privilege Escalation - Kerberos Resource Based Constrained Delegation Attack]], [[Resource Based Constrained Delegation + Fake Machine Account (AD)]]
- [ ] [[AD Privilege Escalation - DNSAdmins Group]]
- [ ] MSSQL Attacks 
	- [ ] [[MSSQL Discovery (AD)]]
	- [ ] [[MSSQL Execution (AD)]]
	- [ ] [[MSSQL Techniques (AD)]]
	- [ ] [[MSSQL NTLM Relay Attack (AD)]]
	- [ ] [[MSSQL Privilege Escalation (AD)]]
	- [ ] [[MSSQL Links Lateral Movement (AD)]]
	- [ ] [[MSSQL Custom Assemblies Execution (AD)]]
	- [ ] [[MSSQL Links Local Privilege Escalation (AD)]]
	- [ ] [[MSSQL Credential Acces via UNC Path Injection (AD)]]
	- [ ] [[AD Privilege Escalation - MSSQL CRTE]]
- [ ] Cross Domain Attacks
	- [ ] [[AD Privilege Escalation - XDomain ADCS Enrolee Supplies Subject Abuse]]
	- [ ] [[AD Privilege Escalation - XDomain Azure AD Integration Attacks]]
	- [ ] [[AD Privilege Escalation - XDomain Trust Attacks]]
- [ ] [[AD Privilege Escalation - ADCS Shadow Credentials]]
- [ ] Cross Forest Attacks
	- [ ] [[AD Privilege Escalation - XForest Kerberoasting Attack]]
	- [ ] [[AD Privilege Escalation - XForest Kerberos Unconstrained Delegation]]
	- [ ] [[AD Privilege Escalation - XForest Kerberos Constrained Delegation]]
	- [ ] [[AD Privilege Escalation - XForest FSP Abuse]]
	- [ ] [[AD Privilege Escalation - XForest PAM Trust Abuse]]

*Note*: Perform different privilege escalation techniques, write down how they were performed and their output below.

*Useful Links*: When compromising a new privileged user, you can use the following methodology to move laterally and dump credentials [[AD - Payload Delivery]]. Check out [[Credential Access (Active Directory)]] for syntax.

```ad-summary
title: Title 
collapse:true


```

```ad-summary
title: Title 
collapse:true


```

```ad-summary
title: Title 
collapse:true


```

*Note*: Every time you compromise a new user/group/computer, remember to go back and enumerate *interesting ACLs* and *local admin access* using them and also impersonate them and run `Find-WMILocalAdminAccess.ps1` `Find-PSRemotingLocalAdminAccess.ps1` to check for local admin access.

## Persistence

### Checklist

- [ ] [[Persistence via Kerberos Tickets (AD)]] (To-Do, split this note in each category)
	- [ ] Silver Tickets
	- [ ] Golden Tickets
	- [ ] Diamond Tickets
- [ ] [[Persistence via msDS-AllowedToDelegateTo ACE (AD)]]
- [ ] [[Persistence via Scheduled Tasks (AD)]]
- [ ] [[Persistence via Skeleton Key (AD)]]
- [ ] [[Persistence via DSRM Password (AD)]]
- [ ] [[Persistence via AdminSDHolder ACE (AD)]]
- [ ] [[Persistence via ACE Rights Abuse (AD)]]
- [ ] [[Persistence via Security Descriptor ACE (AD)]]
- [ ] [[Persistence via Custom SSP (AD)]]
- [ ] [[Persistence via DCShadow (AD)]]
- [ ] [[Persistence via Golden gMSA (AD)]]

*Note*: Establish persistence, write down how it was performed and its output below. Add backdoors to `Credentials` file.

```ad-summary
title:Title
collapse:true 
```

```ad-summary
title: Title 
collapse:true
```

```ad-summary
title: Title 
collapse:true
```
