Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = fso.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
python = fso.BuildPath(scriptDir, ".venv\Scripts\python.exe")
bat = fso.BuildPath(scriptDir, "sentinel.bat")

If Not fso.FileExists(pythonw) Then
    pythonw = python
End If

If fso.FileExists(pythonw) Then
    WshShell.Run Chr(34) & pythonw & Chr(34) & " -m sentinel.main run", 0, False
Else
    WshShell.Run Chr(34) & bat & Chr(34) & " --hidden run", 0, False
End If
