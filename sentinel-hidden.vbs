Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = fso.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
python = fso.BuildPath(scriptDir, ".venv\Scripts\python.exe")

If fso.FileExists(pythonw) Then
    WshShell.Run Chr(34) & pythonw & Chr(34) & " --hidden -m sentinel.main run", 0, False
ElseIf fso.FileExists(python) Then
    WshShell.Run Chr(34) & python & Chr(34) & " --hidden -m sentinel.main run", 0, False
End If
