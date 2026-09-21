Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = fso.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")

If Not fso.FileExists(pythonw) Then
    WScript.Quit 1
End If

WshShell.Run Chr(34) & pythonw & Chr(34) & " --hidden -m sentinel.main run", 0, False
