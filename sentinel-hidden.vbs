Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & "%~dp0sentinel.bat" & Chr(34) & " " & Chr(34) & "run" & Chr(34), 0, False
