@echo off
copy "%~dp0\asmmap64.sys" "%WINDIR%\system32\drivers\asmmap64.sys"
sc create asmmap64 binPath= system32\drivers\asmmap64.sys type= kernel
sc start asmmap64
echo Driver loaded, fire up the exploit now then press a key when exploit has been done.
echo If you see any access denied, close this and relaunch the bat as Administrator.
echo DO NOT PRESS ANY KEY UNTIL YOU HAVE FINISHED LAUNCHING THE EXPLOIT
pause
PING localhost -n 2 >NUL
sc stop asmmap64
sc delete asmmap64
del "%WINDIR%\system32\drivers\asmmap64.sys"
PING localhost -n 2 >NUL
sc stop asmmap64
sc delete asmmap64
del "%WINDIR%\system32\drivers\asmmap64.sys"
PING localhost -n 2 >NUL
echo Cya
