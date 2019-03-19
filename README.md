# Set-ImageFileExecutionOptionDebugger

Set a debugger to be launched when a target executable is launched. The intention of creating the IFEO registry key is to give developers the option to debug their software by attaching any program to any executable using a registry key. The debugger will be launched with SYSTEM priviledges. This leads to a simple, high-priviledge, and fileless persistence method that can be launched from a login screen without the need for valid credentials.

## Arguments

| Argument | Default | Description |
| --- | --- | --- |
| -Executable | sethc.exe | The executable filename to setup a debugger on. |
| -Debugger | C:\Windows\System32\cmd.exe | The "debugger" binary to launch when the target executable is loaded. |

## Examples

```powershell
Set-ImageFileExecutionOptionDebugger -Executable "Magnify.exe" -Debugger "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

## References

- [https://blog.malwarebytes.com/101/2015/12/an-introduction-to-image-file-execution-options/](https://blog.malwarebytes.com/101/2015/12/an-introduction-to-image-file-execution-options/)