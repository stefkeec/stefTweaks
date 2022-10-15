reg add "HKLM\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f

sc config XboxGipSvc start= auto
sc config XblAuthManager start= auto
sc config XblGameSave start= auto
sc config XboxNetApiSvc start= auto

net start XboxGipSvc
net start XblAuthManager
net start XblGameSave 
net start XboxNetApiSvc