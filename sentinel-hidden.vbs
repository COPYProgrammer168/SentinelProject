Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = fso.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
python = fso.BuildPath(scriptDir, ".venv\Scripts\python.exe")
bat = fso.BuildPath(scriptDir, "sentinel.bat")

launchCmd = ""
If fso.FileExists(pythonw) Then
    launchCmd = Chr(34) & pythonw & Chr(34) & " -m sentinel.main run"
ElseIf fso.FileExists(python) Then
    launchCmd = Chr(34) & python & Chr(34) & " -m sentinel.main run"
ElseIf fso.FileExists(bat) Then
    launchCmd = Chr(34) & bat & Chr(34) & " --hidden run"
End If

If launchCmd <> "" Then
    WshShell.Run "cmd /c " & launchCmd & " >NUL 2>&1", 0, False
End If
