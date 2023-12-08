@ECHO OFF & SETLOCAL EnableDelayedExpansion
COLOR 0F

SET long=false

systeminfo
ECHO.

wmic qfe get Caption,Description,HotFixID,InstalledOn | more

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit 2>nul
ECHO.

REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager 2>nul
ECHO.

ECHO.   [i] Check what is being logged
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>nul
ECHO.

REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL 2>nul

REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags 2>nul
ECHO.

reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential 2>nul
ECHO.
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA 2>nul
ECHO.

WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more 

reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 2>nul

ECHO.PowerShell v2 Version:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion 2>nul
ECHO.PowerShell v5 Version:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion 2>nul
ECHO.Transcriptions Settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription 2>nul
ECHO.Module logging settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging 2>nul
ECHO.Scriptblog logging settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging 2>nul
ECHO.
ECHO.PS default transcript history
dir %SystemDrive%\transcripts\ 2>nul
ECHO.
ECHO.Checking PS history file
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
ECHO.

(wmic logicaldisk get caption 2>nul | more) || (fsutil fsinfo drives 2>nul)
ECHO.
set
ECHO.

ECHO.
dir /b "C:\Program Files" "C:\Program Files (x86)" | sort
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"
IF exist C:\Windows\CCM\SCClient.exe ECHO.SCCM is installed (installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading)
ECHO.

IF exist "%LOCALAPPDATA%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" ECHO.Found: RDCMan.settings in %AppLocal%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings, check for credentials in .rdg files
ECHO.

reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ 2>nul | findstr /i "wuserver" | findstr /i "http://"
ECHO.

tasklist /SVC
ECHO.
ECHO.   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('ECHO.%%x') do (
		icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
	)
)
ECHO.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('ECHO.%%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
)
ECHO.

::(autorunsc.exe -m -nobanner -a * -ct /accepteula 2>nul || wmic startup get caption,command 2>nul | more & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. & ^
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab informa")
ECHO.

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
ECHO.

net share
ECHO.

ipconfig  /all
ECHO.

netstat -ano | findstr /i listen
ECHO.

netsh firewall show state
netsh firewall show config
ECHO.

arp -A
ECHO.

route print
ECHO.

type C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#"

ipconfig /displaydns | findstr "Record" | findstr "Name Host"
ECHO.

for /f "tokens=4 delims=: " %%a in ('netsh wlan show profiles ^| find "Profile "') do (netsh wlan show profiles name=%%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & ECHO.)

net user %username%
net user %USERNAME% /domain 2>nul
whoami /all
ECHO.

net user
ECHO.

net localgroup
ECHO.

REM seems to be localised
net localgroup Administrators 2>nul
net localgroup Administradores 2>nul
ECHO. 

quser
ECHO. 

klist
ECHO. 

ECHO.   [i] Any passwords inside the clipboard?
powershell -command "Get-Clipboard" 2>nul
ECHO.

for /f "tokens=2 delims='='" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos usuarios %username%" && ECHO.
)
ECHO.

for /f %%a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv >nul 2>&1 & reg save %%a %temp%\reg.hiv >nul 2>&1 && reg restore %%a %temp%\reg.hiv >nul 2>&1 && ECHO.You can modify %%a
ECHO.

for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		ECHO.%%~s ^| findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (ECHO.%%n && ECHO.%%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && ECHO.
	)
)
::wmic service get name,displayname,pathname,startmode | more | findstr /i /v "C:\\Windows\\system32\\" | findstr /i /v """
ECHO.
::

for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. )
ECHO.

cmdkey /list
ECHO.

powershell -command "Get-ChildItem %appdata%\Microsoft\Protect" 2>nul
powershell -command "Get-ChildItem %localappdata%\Microsoft\Protect" 2>nul
ECHO.Looking inside %appdata%\Microsoft\Credentials\
ECHO.
dir /b/a %appdata%\Microsoft\Credentials\ 2>nul 
ECHO.
ECHO.Looking inside %localappdata%\Microsoft\Credentials\
ECHO.
dir /b/a %localappdata%\Microsoft\Credentials\ 2>nul
ECHO.

IF EXIST %WINDIR%\sysprep\sysprep.xml ECHO.%WINDIR%\sysprep\sysprep.xml exists. 
IF EXIST %WINDIR%\sysprep\sysprep.inf ECHO.%WINDIR%\sysprep\sysprep.inf exists. 
IF EXIST %WINDIR%\sysprep.inf ECHO.%WINDIR%\sysprep.inf exists. 
IF EXIST %WINDIR%\Panther\Unattended.xml ECHO.%WINDIR%\Panther\Unattended.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend.xml ECHO.%WINDIR%\Panther\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattend.xml ECHO.%WINDIR%\Panther\Unattend\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattended.xml ECHO.%WINDIR%\Panther\Unattend\Unattended.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattend.xml ECHO.%WINDIR%\System32\Sysprep\unattend.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattended.xml ECHO.%WINDIR%\System32\Sysprep\unattended.xml exists.
IF EXIST %WINDIR%\..\unattend.txt ECHO.%WINDIR%\..\unattend.txt exists.
IF EXIST %WINDIR%\..\unattend.inf ECHO.%WINDIR%\..\unattend.inf exists. 
ECHO.

IF EXIST %WINDIR%\repair\SAM ECHO.%WINDIR%\repair\SAM exists. 
IF EXIST %WINDIR%\System32\config\RegBack\SAM ECHO.%WINDIR%\System32\config\RegBack\SAM exists.
IF EXIST %WINDIR%\System32\config\SAM ECHO.%WINDIR%\System32\config\SAM exists.
IF EXIST %WINDIR%\repair\SYSTEM ECHO.%WINDIR%\repair\SYSTEM exists.
IF EXIST %WINDIR%\System32\config\SYSTEM ECHO.%WINDIR%\System32\config\SYSTEM exists.
IF EXIST %WINDIR%\System32\config\RegBack\SYSTEM ECHO.%WINDIR%\System32\config\RegBack\SYSTEM exists.
ECHO.

cd %ProgramFiles% 2>nul
dir /s SiteList.xml 2>nul
cd %ProgramFiles(x86)% 2>nul
dir /s SiteList.xml 2>nul
cd "%windir%\..\Documents and Settings" 2>nul
dir /s SiteList.xml 2>nul
cd %windir%\..\Users 2>nul
dir /s SiteList.xml 2>nul
ECHO.

cd "%SystemDrive%\Microsoft\Group Policy\history" 2>nul
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml 2>nul
cd "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" 2>nul
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml 2>nul
ECHO.

cd "%SystemDrive%\Users"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json 2>nul
cd "%windir%\..\Documents and Settings"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json 2>nul
ECHO.

IF EXIST %systemroot%\system32\inetsrv\appcmd.exe ECHO.%systemroot%\system32\inetsrv\appcmd.exe exists. 
ECHO.

ECHO.Looking inside HKCU\Software\ORL\WinVNC3\Password
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul
ECHO.Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password 2>nul
ECHO.Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"
ECHO.Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s 2>nul
ECHO.Looking inside HKCU\Software\TightVNC\Server
reg query HKCU\Software\TightVNC\Server 2>nul
ECHO.Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>nul
ECHO.Looking inside HKCU\Software\OpenSSH\Agent\Keys
reg query HKCU\Software\OpenSSH\Agent\Keys /s 2>nul
cd %USERPROFILE% 2>nul && dir /s/b *password* == *credential* 2>nul
cd ..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..
dir /s/b /A:-D RDCMan.settings == *.rdg == SCClient.exe == *_history == .sudo_as_admin_successful == .profile == *bashrc == httpd.conf == *.plan == .htpasswd == .git-credentials == *.rhosts == hosts.equiv == Dockerfile == docker-compose.yml == appcmd.exe == TypedURLs == TypedURLsTime == History == Bookmarks == Cookies == "Login Data" == places.sqlite == key3.db == key4.db == credentials == credentials.db == access_tokens.db == accessTokens.json == legacy_credentials == azureProfile.json == unattend.txt == access.log == error.log == *.gpg == *.pgp == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12 == *.der == *.csr == *.cer == known_hosts == id_rsa == id_dsa == *.ovpn == anaconda-ks.cfg == hostapd.conf == rsyncd.conf == cesi.conf == supervisord.conf == tomcat-users.xml == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == unattend.xml == unattended.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == groups.xml == services.xml == scheduledtasks.xml == printers.xml == drives.xml == datasources.xml == php.ini == https.conf == https-xampp.conf == httpd.conf == my.ini == my.cnf == access.log == error.log == server.xml == SiteList.xml == ConsoleHost_history.txt == setupinfo == setupinfo.bak 2>nul | findstr /v ".dll"
cd inetpub 2>nul && (dir /s/b web.config == *.log & cd ..)
ECHO.

:ExtendedDriveScan
if "%long%" == "true" (
    CALL :ColorLine " %E%33m[+]%E%97m REGISTRY WITH STRING pass OR pwd"
	reg query HKLM /f passw /t REG_SZ /s
	reg query HKCU /f passw /t REG_SZ /s
	reg query HKLM /f pwd /t REG_SZ /s
	reg query HKCU /f pwd /t REG_SZ /s
	ECHO.
	ECHO.   [i] Iterating through the drives
	ECHO.
	for /f %%x in ('wmic logicaldisk get name^| more') do (
		set tdrive=%%x
		if "!tdrive:~1,2!" == ":" (
			%%x
            CALL :ColorLine " %E%33m[+]%E%97m FILES THAT CONTAINS THE WORD PASSWORD WITH EXTENSION: .xml .ini .txt *.cfg *.config"
	        findstr /s/n/m/i password *.xml *.ini *.txt *.cfg *.config 2>nul | findstr /v /i "\\AppData\\Local \\WinSxS ApnDatabase.xml \\UEV\\InboxTemplates \\Microsoft.Windows.Cloud \\Notepad\+\+\\ vmware cortana alphabet \\7-zip\\" 2>nul
            ECHO.
            CALL :ColorLine " %E%33m[+]%E%97m FILES WHOSE NAME CONTAINS THE WORD PASS CRED or .config not inside \Windows\"
            dir /s/b *pass* == *cred* == *.config* == *.cfg 2>nul | findstr /v /i "\\windows\\"  
            ECHO.
		)
	)
	
)


ECHO.Scan complete.
PAUSE >NUL 
EXIT /B

:::-Subroutines

:ColorLine
SET "CurrentLine=%~1"
FOR /F "delims=" %%A IN ('FORFILES.EXE /P %~dp0 /M %~nx0 /C "CMD /C ECHO.!CurrentLine!"') DO ECHO.%%A
EXIT /B