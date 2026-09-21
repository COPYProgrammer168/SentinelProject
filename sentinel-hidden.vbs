Set WshShell = CreateObject("WScript.Shell")
scriptDir = Left(WScript.ScriptFullName, Len(WScript.ScriptFullName) - Len(WScript.ScriptName))
pythonw = scriptDir & ".venv\Scripts\pythonw.exe"
python = scriptDir & ".venv\Scripts\python.exe"
bat = scriptDir & "sentinel.bat"

If Not CreateObject("Scripting.FileSystemObject").FileExists(pythonw) Then
    pythonw = python
End If

If CreateObject("Scripting.FileSystemObject").FileExists(pythonw) Then
    WshShell.Run Chr(34) & pythonw & Chr(34) & " -m sentinel.main run", 0, False
Else
    WshShell.Run Chr(34) & bat & Chr(34) & " --hidden run", 0, False
End If
