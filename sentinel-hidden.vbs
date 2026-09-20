Set WshShell = CreateObject("WScript.Shell")
cmd = ""
For i = 0 To WScript.Arguments.Count - 1
    cmd = cmd & Chr(34) & WScript.Arguments(i) & Chr(34) & " "
Next
WshShell.Run cmd, 0, False
