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

REM 2. Disable Ctrl+Alt+Delete requirement
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 1 /f

REM 3. Set password policies
net accounts /uniquepw:5
net accounts /maxpwage:90
net accounts /minpwage:15
net accounts /minpwlen:14

REM 4. Export current security policies
secedit /export /cfg %TEMP%\secpol.cfg

REM 5. Enable Password Complexity
findstr /r "PasswordComplexity" %TEMP%\secpol.cfg || echo "PasswordComplexity = 1" >> %TEMP%\secpol.cfg
secedit /configure /db %TEMP%\secedit.sdb /cfg %TEMP%\secpol.cfg

REM 6. Enable Clear Text Password
secedit /export /cfg %TEMP%\secpol.cfg
findstr /r "ClearTextPassword" %TEMP%\secpol.cfg || echo "ClearTextPassword = 0" >> %TEMP%\secpol.cfg
secedit /configure /db %TEMP%\secedit.sdb /cfg %TEMP%\secpol.cfg

REM 7. Set auditing policies
auditpol /set /subcategory:"Computer Account Management" /success:enable
auditpol /set /subcategory:"File Share" /failure:enable
auditpol /set /subcategory:"Logon" /success:enable

REM 8. Enable Windows Defender Firewall
netsh advfirewall set allprofiles state on

REM 9. Start Windows Defender
sc start windefend

REM 10. Disable Guest account
net user guest /active:no

REM 11. Configure security settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
net accounts /lockoutduration:30
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:30

REM 12. Enable SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "warn" /f

REM 13. Limit blank password usage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

REM 14. Configure anonymous access restrictions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

REM 15. Deny access to Everyone from the network
net localgroup "Deny access to this computer from the network" Everyone /add

REM 16. Disable Remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

REM 17. Start the event log service
sc config eventlog start= auto
sc start eventlog

REM 18. Enable security signatures for LanmanWorkstation
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f

REM 19. Generate a security report
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

REM 20. Check if Microsoft Defender Antivirus is installed
sc query WinDefend >nul 2>&1
IF ERRORLEVEL 1 (
    echo ALERT: Microsoft Defender Antivirus is not installed on this machine! >> "%outputFile%"
    echo ALERT: Microsoft Defender Antivirus is not installed on this machine!
) ELSE (
    echo Microsoft Defender Antivirus is installed. >> "%outputFile%"
    echo Microsoft Defender Antivirus is installed.
)

REM 21. Check if Windows Defender Firewall is running
sc query mpssvc >nul 2>&1
IF ERRORLEVEL 1 (
    echo ALERT: Windows Defender Firewall is not running! >> "%outputFile%"
    echo ALERT: Windows Defender Firewall is not running!
) ELSE (
    echo Windows Defender Firewall is running. >> "%outputFile%"
    echo Windows Defender Firewall is running.
)

REM 22. Check if ".exe" files are excluded in Windows Defender
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

REM 23. Check DNS Server service status and alert if stopped or disabled
echo Checking DNS Server service status... >> "%outputFile%"
sc query DNS >nul 2>&1
IF ERRORLEVEL 1 (
    echo ALERT: DNS Server service is not installed on this machine! >> "%outputFile%"
    echo ALERT: DNS Server service is not installed on this machine!
) ELSE (
    for /f "tokens=3" %%A in ('sc query DNS ^| findstr "STATE"') do (
        if "%%A"=="STOPPED" (
            echo ALERT: DNS Server service is stopped! >> "%outputFile%"
            echo Please open Services management console to start the service. >> "%outputFile%"
            echo 1. Press Windows + R, type "services.msc", and press Enter. >> "%outputFile%"
            echo 2. Locate "DNS Server" service in the list. >> "%outputFile%"
            echo 3. Right-click on it, select "Properties," change the Startup type to "Automatic," and click "Start." >> "%outputFile%"
            echo 4. Click OK to apply the changes. >> "%outputFile%"
            echo ALERT: DNS Server service is stopped!
        ) ELSE (
            echo DNS Server service is running. >> "%outputFile%"
            echo To disable the DNS Server service, do the following: >> "%outputFile%"
            echo 1. Press Windows + R, type "services.msc", and press Enter to open Services. >> "%outputFile%"
            echo 2. Scroll down and double-click on DNS Server to open a Properties window. >> "%outputFile%"
            echo 3. Change the Startup type to Disabled to prevent the service from starting automatically, then click Stop to stop the service. >> "%outputFile%"
            echo 4. Click OK to apply the changes and close the Properties window. >> "%outputFile%"
        )
    )
)

REM 24. Check for Everyone access settings
echo Checking "Everyone may not access this computer from the network" setting... >> "%outputFile%"
powershell -Command "Get-LocalGroupMember -Group 'Administrators' | Where-Object { $_.Name -eq 'Everyone' }"
IF ERRORLEVEL 1 (
    echo ALERT: "Everyone may not access this computer from the network" is not configured properly! >> "%outputFile%"
    echo To fix this, do the following: >> "%outputFile%"
    echo 1. Press the Windows key + R to open the Run dialog. >> "%outputFile%"
    echo 2. Type "secpol.msc" and press Enter to open the Local Security Policy. >> "%outputFile%"
    echo 3. Navigate to Security Settings → Local Policies → User Rights Assignment. >> "%outputFile%"
    echo 4. Double-click on "Access this computer from the network" to bring up a Properties window. >> "%outputFile%"
    echo 5. Select "Everyone," click Remove, then click OK to apply the setting and close the Properties window. >> "%outputFile%"
) ELSE (
    echo "Everyone may not access this computer from the network" is properly configured. >> "%outputFile%"
)

echo Checking "Let Everyone permissions apply to anonymous users" setting... >> "%outputFile%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EveryonePermissionsApplyToAnonymous" | findstr "0x0"
IF ERRORLEVEL 1 (
    echo ALERT: "Let Everyone permissions apply to anonymous users" is not configured properly! >> "%outputFile%"
    echo To fix this, do the following: >> "%outputFile%"
    echo 1. Press the Windows key + R to open the Run dialog. >> "%outputFile%"
    echo 2. Type "secpol.msc" and press Enter to open the Local Security Policy. >> "%outputFile%"
    echo 3. Navigate to Security Settings → Local Policies → Security Options. >> "%outputFile%"
    echo 4. Double-click on "Network access: Let Everyone permissions apply to anonymous users" to bring up a Properties window. >> "%outputFile%"
    echo 5. Select "Disabled" and click OK to apply the setting and close the Properties window. >> "%outputFile%"
) ELSE (
    echo "Let Everyone permissions apply to anonymous users" is properly configured. >> "%outputFile%"
)

REM Finish
echo Security report generated successfully at %outputFile%.
endlocal
pause
