@echo off
sc stop ftpsvc
sc config ftpsvc start=disabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 1 /f
net accounts /uniquepw:5
net accounts /maxpwage:90
net accounts /minpwage:15
net accounts /minpwlen:14
secedit /export /cfg %TEMP%\secpol.cfg
findstr /r "PasswordComplexity" %TEMP%\secpol.cfg || echo "PasswordComplexity = 1" >> %TEMP%\secpol.cfg
secedit /configure /db %TEMP%\secedit.sdb /cfg %TEMP%\secpol.cfg
secedit /export /cfg %TEMP%\secpol.cfg
findstr /r "ClearTextPassword" %TEMP%\secpol.cfg || echo "ClearTextPassword = 0" >> %TEMP%\secpol.cfg
secedit /configure /db %TEMP%\secedit.sdb /cfg %TEMP%\secpol.cfg
auditpol /set /subcategory:"Computer Account Management" /success:enable
netsh advfirewall set allprofiles state on
auditpol /set /subcategory:"File Share" /failure:enable
sc start windefend
net user guest /active:no
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
net accounts /lockoutduration:30
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:30
auditpol /set /subcategory:"Logon" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "warn" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
secedit /export /cfg %TEMP%\secpol.cfg
findstr /r "RestrictAnonymousSAM" %TEMP%\secpol.cfg || echo "RestrictAnonymousSAM = 1" >> %TEMP%\secpol.cfg
secedit /configure /db %TEMP%\secedit.sdb /cfg %TEMP%\secpol.cfg
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
sc config eventlog start= auto
sc start eventlog
::make an output file in downloads
setlocal
set outputFile=%USERPROFILE%\Downloads\security_report.txt
echo Security Report > "%outputFile%"
echo ================== >> "%outputFile%"
echo. >> "%outputFile%"
echo Users with Administrator Privileges: >> "%outputFile%"
net localgroup administrators >> "%outputFile%"
echo. >> "%outputFile%"
echo Unauthorized File Shares: >> "%outputFile%"
net share >> "%outputFile%"
echo. >> "%outputFile%"
echo Installed Applications: >> "%outputFile%"
echo ===================== >> "%outputFile%"
wmic product get name >> "%outputFile%"
echo. >> "%outputFile%"
echo Security Report generated at: %outputFile%
echo Done.
pause