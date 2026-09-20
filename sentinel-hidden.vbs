Set WshShell = CreateObject("WScript.Shell")
batchPath = Left(WScript.ScriptFullName, Len(WScript.ScriptFullName) - 4) & "bat"
WshShell.Run Chr(34) & batchPath & Chr(34) & " --hidden run", 0, False
