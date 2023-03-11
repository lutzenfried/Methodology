# Local Privilege Escalation Techniques - Windows Edition

- UAC and bypass
- Access Token Manipulation
- Exposed credentials (Azure, PowerShell history,...)
- Missing patches
- Automated deployment and Autologon passwords in clear text
- AlwaysInstallElevated (Any User can run MSI as System)
- Misconfigured Services
- Unquoted path
- DLL Hijacking

#### Tools
- PowerUP
- BeRoot
- [Privesc](https://github.com/enjoiz/Privesc)

#### PowerUp
Get services with unquoted paths and a space in their name
```
Get-ServiceUnquoted -Verbose
```

Get services where the currentuser can write to its binary path or change argument to the binary
```
Get-ModifiableServicefile -Verbose
```

Get the services whose configuration current user can modify
```
Get-ModifiableService -Verbose
```

Open a reverse shell listening using powercat
```
powercat -l -p 4444 -v -t 1024
```