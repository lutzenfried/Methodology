- [MacOS Intrusion](#macos-intrusion)
    - [MacOS 101](#macos-101)
    - [Initial Access](#initial-access)
      - [Installer Package](#installer-package)
      - [App Bundles/Package](#app-bundlespackage)
      - [AppleScript URL](#applescript-url)
      - [2FA Phishing](#2fa-phishing)
      - [MacOS payload generator](#macos-payload-generator)
      - [Phishing using office](#phishing-using-office)
      - [C2](#c2)
    - [User Persistence](#user-persistence)
      - [Plist - (LaunchAgents)](#plist---launchagents)
      - [Login items](#login-items)
      - [Folder action scripts](#folder-action-scripts)
      - [JXA persistence](#jxa-persistence)
      - [Swift persistence scripts](#swift-persistence-scripts)
      - [Authorization Plugin](#authorization-plugin)
      - [Dock shortcut modification](#dock-shortcut-modification)
      - [Atom Init script](#atom-init-script)
      - [SSHrc persistence](#sshrc-persistence)
      - [Vim plugin](#vim-plugin)
      - [Sublim text app script](#sublim-text-app-script)
      - [ZSH profile](#zsh-profile)
      - [XBar Plugin](#xbar-plugin)
    - [Root Persistence](#root-persistence)
      - [Launch Daemons](#launch-daemons)
      - [Emond](#emond)
      - [Dylib persistence](#dylib-persistence)
    - [Privilege Escalation](#privilege-escalation)
      - [System creds](#system-creds)
      - [Terminal history](#terminal-history)
      - [Chrome "Cookie Crimes"](#chrome-cookie-crimes)
      - [Helper tool](#helper-tool)
      - [Prompt phishing](#prompt-phishing)
    - [Lateral movement](#lateral-movement)
      - [MacHound](#machound)
      - [BiFrost](#bifrost)
      - [SwiftBelt](#swiftbelt)
      - [Living Of the Orchard Bins](#living-of-the-orchard-bins)
    - [Credential Access](#credential-access)
      - [Keychain](#keychain)
      - [Phishing using prompt](#phishing-using-prompt)
    - [Exfiltration](#exfiltration)
      - [Exfiltrate Google Services](#exfiltrate-google-services)
      - [Exfiltrating Jira](#exfiltrating-jira)
      - [Slack exfiltration](#slack-exfiltration)
      - [Impact](#impact)
    - [MacOS Security Features](#macos-security-features)
      - [Code Signing](#code-signing)
      - [Entitlements](#entitlements)
      - [System Integrity Protection (SIP)](#system-integrity-protection-sip)
      - [TCC](#tcc)
      - [Quarantine](#quarantine)
      - [GateKeeper](#gatekeeper)
      - [XProtect](#xprotect)
      - [Extended Attributes](#extended-attributes)
      - [Application sandbox](#application-sandbox)
      - [Notarization](#notarization)
      - [Apple Endpoint Security Framework](#apple-endpoint-security-framework)
    - [Offensive MacOS - Training / Cert](#offensive-macos---training--cert)
      - [HITB - Exploiting Directory PErmissions on MacOS](#hitb---exploiting-directory-permissions-on-macos)
      - [Objective-See](#objective-see)
      - [Offensive MacOs Repo](#offensive-macos-repo)
      - [DEF CON 29 - Cedric Owens - Gone Apple Pickin: Red Teaming MacOS Environments in 2021](#def-con-29---cedric-owens---gone-apple-pickin-red-teaming-macos-environments-in-2021)
      - [CVE-2021-30657 - Patrick Wardle Explanation (Objective-See)](#cve-2021-30657---patrick-wardle-explanation-objective-see)
      - [Awesome MacOS Red Teaming](#awesome-macos-red-teaming)
      - [Mac Security Conference](#mac-security-conference)

# MacOS Intrusion

[Mitre MacOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/)

### MacOS 101

| Windows                    | MacOS                                    |
| -------------------------- |:----------------------------------------:|
| Registry                   | Property List Files (.plist)             |
| Windows Event Logs         | Apple Unified Logging                    |
| CMD / PSH                  | Terminal.app (bash / zsh)t               |
| Portable Executable (PE)   | Mach-O Executable                        |
| DLL                        | Dynamic Library (Dylib)                  |
| %APPDATA%                  | ~/Library/Application Support/           |
| SYSTEM / Administrators    | Root / admin                             |
| LSASS                      | Keychain                                 |
| User Account Control (UAC) | Transparency, Consent, and Control (TCC) |
| Privileges                 | Entitlements                             |
| .lnk                       | Dock Shortcuts                           |
| -                          | Application Bundles (.app)               |


### Initial Access

#### Installer Package

#### App Bundles/Package

#### AppleScript URL
- https://wojciechregula.blog/post/macos-red-teaming-initial-access-via-applescript-url/

#### 2FA Phishing
EvilNginx

#### MacOS payload generator
- https://github.com/D00MFist/Mystikal

#### Phishing using office
Payload execution will probably be sandboxed.
- https://github.com/cldrn/macphish
- https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c

#### C2
- https://github.com/its-a-feature/Mythic
- https://github.com/kareman/SwiftShell
- https://github.com/cedowens/MacC2 

### User Persistence
#### Plist - (LaunchAgents)
- https://theevilbit.github.io/beyond/beyond_intro/
#### Login items

#### Folder action scripts

#### JXA persistence
- https://github.com/D00MFist/PersistentJXA

#### Swift persistence scripts
- https://github.com/cedowens/Persistent-Swift

#### Authorization Plugin

#### Dock shortcut modification

#### Atom Init script

#### SSHrc persistence

#### Vim plugin 
- https://github.com/D00MFist/PersistentJXA/blob/master/VimPluginPersistence.js

#### Sublim text app script
- https://github.com/D00MFist/PersistentJXA/blob/master/SublimeTextPluginPersistence.js

#### ZSH profile

#### XBar Plugin
- https://github.com/D00MFist/PersistentJXA/blob/master/xbarUtil.py

### Root Persistence
#### Launch Daemons

#### Emond

#### Dylib persistence

### Privilege Escalation
- https://ofiralmkias.medium.com/bypassing-macos-sandbox-performing-privilege-escalation-and-more-2a020efd7ceb

#### System creds
- aws
- gcp
- azure
- SSH keys

#### Terminal history
Look for ZSH, Bash and other terminal history.  

#### Chrome "Cookie Crimes"
- https://mango.pdf.zone/stealing-chrome-cookies-without-a-password
- https://github.com/defaultnamehere/cookie_crimes

```
git clone https://github.com/defaultnamehere/cookie_crimes.git
cd cookie_crimes/
./cookie_crimes_macos.sh
```

#### Helper tool
- https://www.sentinelone.com/blog/macos-red-team-spoofing-privileged-helpers-and-others-to-gain-root/

#### Prompt phishing
Prompt user for credentials based on predefined context.  

### Lateral movement
#### MacHound
- https://github.com/XMCyber/MacHound

#### BiFrost
- https://github.com/its-a-feature/bifrost

#### SwiftBelt
- https://github.com/cedowens/SwiftBelt

#### Living Of the Orchard Bins
- https://www.loobins.io/

### Credential Access
#### Keychain
If root access you can retrieve and grab the **keychain** db and take offline using chainbreaker.
- https://github.com/n0fate/chainbreaker  

#### Phishing using prompt

### Exfiltration
#### Exfiltrate Google Services
- [gd-thief](https://github.com/antman1p/GD-Thief)
- [gdir-thief](https://github.com/antman1p/GD-Thief)
- [conf-thief](https://github.com/antman1p/Conf-Thief)
  
#### Exfiltrating Jira
- [jir-thief](https://github.com/antman1p/Jir-Thief)

#### Slack exfiltration
- [slackhound](https://github.com/BojackThePillager/Slackhound)
- [slackpirate](https://github.com/emtunc/SlackPirate)
  
#### Impact

### MacOS Security Features

#### Code Signing
- Introduced MacOS X Lion (10.7)
- Cryptographic signature embedded in app using (developer) certificate
- Verification handled by : **com.apple.driver.AppleMobileFileIntegrity.kext** kernel extension and **/usr/libexec/amfid** daemon

#### Entitlements
Granular set of permissions that allow or deny an application access to specific system resources or privileges. (Fine-grained rights)

Displaying entitlements for a binary or application
```
codesign –dv --entitlement - ./binary
```

We conducting red team operation, operator should look for processes with desired entitlements, **child process inherits the entitlements of the parent** by default.  

#### System Integrity Protection (SIP)

#### TCC
TCC - Transaprency, Consent and Control is a mechanis in MacOS to limit and control application access to certain features. Requires user consent to access user data and some system resources.  

--> Similar to Window's UAC (User Account Control), prompting the user if needed permissions.  

- https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc

Folders such as **~** and **/tmp** are not protected by TCC and followings sensitive directories such as:
- ~.ssh
- ~.aws
- ~.config
- gcloud
- credentials.db
- ~.azure

--> If SSH is running you can SSH in locally to get full disk access and bypass TCC.  

```
ssh user@ip "cat ~/Library/Application\ Support/com.apple.TCC/TCC.db"
```

- https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/
- https://www.youtube.com/watch?v=vMGiplQtjTY

#### Quarantine
Quarantine Attribute - q attr.  
- Appended by the OS to files downloaded via browsers (similar to smart screen in Windows world)

--> Using **curl** does not append the quarantine attribute to the file.  

#### GateKeeper

#### XProtect

#### Extended Attributes

Listing extended attributes for a file
```
$ xattr downloadedFile
com.apple.metadata:kMDItemWhereFroms
com.apple.quarantine
```

Deleting quarantine attributes for a file
```
$ xattr -d com.apple.quarantine downloadedFile
$ xattr downloadedFile
com.apple.metadata:kMDItemWhereFroms

```


#### Application sandbox

#### Notarization

#### Apple Endpoint Security Framework

### Offensive MacOS - Training / Cert
- [Specterops - Mac Tradfecraft](https://specterops.io/training/mac-tradecraft/)
- [EXP-312: Advanced macOS Control Bypasses](https://www.offsec.com/courses/exp-312/)

a### MacOS - Resources

- https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse
- https://null-byte.wonderhowto.com/how-to/hacking-macos-perform-privilege-escalation-part-1-file-permissions-abuse-0186331/
- https://null-byte.wonderhowto.com/how-to/hacking-macos-perform-privilege-escalation-part-2-password-phishing-0186332/

#### HITB - Exploiting Directory PErmissions on MacOS
- https://conference.hitb.org/hitblockdown/materials/D1%20-%20Exploiting%20Directory%20Permissions%20on%20MacOS%20-%20Csaba%20Fitzl.pdf

#### Objective-See
- https://objective-see.org/index.html  

#### Offensive MacOs Repo
- https://github.com/its-a-feature/offensive_macos

#### DEF CON 29 - Cedric Owens - Gone Apple Pickin: Red Teaming MacOS Environments in 2021
- https://www.youtube.com/watch?v=IiMladUbL6E

#### CVE-2021-30657 - Patrick Wardle Explanation (Objective-See)
Explanation of some MacOS security feature - Quarantine / GateKeeper / Notarization
- https://www.youtube.com/watch?v=ivjICKYZul0

#### Awesome MacOS Red Teaming
- https://github.com/tonghuaroot/Awesome-macOS-Red-Teaming

#### Mac Security Conference
- https://objectivebythesea.org/v6/index.html

**TO DO**
- Apple Events
- Read all : https://objective-see.org/blog.html
- https://pentester.wtf/blog/2020/specterops-2020-review/
- https://www.youtube.com/watch?v=vMGiplQtjTY
- Office Macros: Application sandbox and escape
- JXA JavaScript For Automation
- https://posts.specterops.io/no-place-like-chrome-122e500e421f
- https://labs.f-secure.com/blog/operationalising-calendar-alerts-persistence-on-macos
- https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf
- https://theevilbit.github.io/posts/macos_persistence_spotlight_importers/
- https://theevilbit.github.io/beyond/
- https://objectivebythesea.org/v2/talks/OBTS_v2_Thomas.pdf
- https://github.com/cedowens/JXA-Runner
- Abuse daemons for privileges escalation (https://github.com/its-a-feature/HealthInspector)
- https://github.com/cedowens/JXA-Runner
- Basically all cedowens repo
    User_Launchdaemons()
    System_Launchdaemons()
- https://www.sentinelone.com/blog/privilege-escalation-macos-malware-the-path-to-root-part-2/
- https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/
- https://wojciechregula.blog/post/macos-red-teaming-bypass-tcc-with-old-apps/
- https://wojciechregula.blog/post/macos-red-teaming-get-ad-credentials-from-nomad/
- https://wojciechregula.blog/tags/tcc/
- https://wojciechregula.blog/post/macos-red-teaming-apple-signed-java/
- https://github.com/tonghuaroot/Awesome-macOS-Red-Teaming
- https://medium.com/red-teaming-with-a-blue-team-mentality/using-macos-internals-for-post-exploitation-b5faaa11e121
- https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox
- https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections
- https://book.hacktricks.xyz/macos-hardening/macos-red-teaming
- https://hitcon.org/2022/slides/Every-authorization-has-its-black-tackling-privilege-escalation-in-macOS.pdf
- https://www.offsec.com/offsec/macos-preferences-priv-escalation/
- https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/
- https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/
- https://www.slideshare.net/wojdwo/abusing-securing-xpc-in-macos-apps
- https://wojciechregula.blog/post/learn-xpc-exploitation-part-1-broken-cryptography/
- http://lockboxx.blogspot.com/2019/09/macos-red-teaming-208-macos-att.html
- https://github.com/usnistgov/macos_security#readme
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-219r1.pdf
- https://www.youtube.com/watch?v=RKidBayaM7c