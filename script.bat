@echo off

REM Set the output file path
setlocal
set outputFile=%USERPROFILE%\Downloads\security_report.txt
echo Security Report > "%outputFile%"
echo ================== >> "%outputFile%"
echo. >> "%outputFile%"

REM 1. Stop and disable the FTP service
sc stop ftpsvc
sc config ftpsvc start=disabled

REM 2. Enable Windows Defender Firewall
netsh advfirewall set allprofiles state on

REM 3. Start Windows Defender
sc start windefend

REM 4. Disable Guest account
net user guest /active:no

REM 5. Configure security settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f

REM 6. Enable SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "warn" /f

REM 7. Limit blank password usage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

REM 8. Configure anonymous access restrictions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

REM 9. Deny access to Everyone from the network
net localgroup "Deny access to this computer from the network" Everyone /add

REM 10. Disable Remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

REM 11. Start the event log service
sc config eventlog start= auto
sc start eventlog

REM 12. Enable security signatures for LanmanWorkstation
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f

REM 13. Generate a security report
echo Users with Administrator Privileges: >> "%outputFile%"
echo. >> "%outputFile%"
net localgroup administrators >> "%outputFile%"
echo. >> "%outputFile%"
echo Unauthorized File Shares: >> "%outputFile%"
net share >> "%outputFile%"
echo. >> "%outputFile%"
echo Installed Applications: >> "%outputFile%"
echo ===================== >> "%outputFile%"
wmic product get name >> "%outputFile%"
echo. >> "%outputFile%"
echo Security Report generated at: %outputFile% >> "%outputFile%"

REM 14. Check if Microsoft Defender Antivirus is installed
sc query WinDefend >nul 2>&1
IF ERRORLEVEL 1 (
    echo ALERT: Microsoft Defender Antivirus is not installed on this machine! >> "%outputFile%"
    echo ALERT: Microsoft Defender Antivirus is not installed on this machine!
) ELSE (
    echo Microsoft Defender Antivirus is installed. >> "%outputFile%"
    echo Microsoft Defender Antivirus is installed.
)

REM 15. Check if Windows Defender Firewall is running
sc query mpssvc >nul 2>&1
IF ERRORLEVEL 1 (
    echo ALERT: Windows Defender Firewall is not running! >> "%outputFile%"
    echo ALERT: Windows Defender Firewall is not running!
) ELSE (
    echo Windows Defender Firewall is running. >> "%outputFile%"
    echo Windows Defender Firewall is running.
)

REM 16. Check if ".exe" files are excluded in Windows Defender
echo Checking if ".exe" files are excluded in Microsoft Defender... >> "%outputFile%"
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | ForEach-Object { if ($_ -eq '.exe') { Write-Host 'ALERT: .exe files are excluded in Defender. This is a security risk!'; exit 1 } }"
IF ERRORLEVEL 1 (
    echo ALERT: ".exe" files are excluded from Microsoft Defender! >> "%outputFile%"
    echo Press the Windows key + R to open the Run dialog. >> "%outputFile%"
    echo In the Run dialog, type "windowsdefender:" (make sure and include a colon at the end) and press Enter to open Windows Security. >> "%outputFile%"
    echo Click Virus & threat protection, then click Manage Settings under Virus & threat protection settings. >> "%outputFile%"
    echo Scroll down and click on Add or remove exclusions under Exclusions. >> "%outputFile%"
    echo If prompted, click Yes in the UAC popup to continue. >> "%outputFile%"
    echo Click on Remove under .exe, then click Remove under exe. >> "%outputFile%"
) ELSE (
    echo No ".exe" file exclusion found in Defender. >> "%outputFile%"
)

REM Finish
echo Security report generated successfully at %outputFile%.
endlocal
pause
