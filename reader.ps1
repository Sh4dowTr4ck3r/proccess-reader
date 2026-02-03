param(
    [Parameter(Mandatory=$true)] [int]$ProcessId,
    [Parameter(Mandatory=$false)] [string]$SearchString = "",
    [Parameter(Mandatory=$false)] [string]$OutputFile = "",
    [Parameter(Mandatory=$false)] [string]$StringsFile = "",
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Private", "Image", "Mapped")]
    [string]$MemType = "All", # New flag for filtering memory type
    [Parameter(Mandatory=$false)] [switch]$CaseInsensitive
)

if (-not ([System.Management.Automation.PSTypeName]"MEMORY_BASIC_INFORMATION").Type) {
    $TypeDef = @"
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    public class MemoryReader {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
    }
"@
    Add-Type -TypeDefinition $TypeDef
}

function Write-Log { param([string]$Msg) Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Msg" }

function Get-ProtectionString {
    param([uint32]$Protect)
    $base = $Protect -band 0xFF
    if ($base -eq 0x04) { return "READ/WRITE" }
    if ($base -eq 0x02) { return "READ_ONLY" }
    if ($base -eq 0x08) { return "WRITECOPY" }
    if ($base -eq 0x20) { return "EXECUTE_READ" }
    if ($base -eq 0x40) { return "EXECUTE_READWRITE" }
    return "0x{0:X}" -f $Protect
}

function Get-TypeString {
    param([uint32]$Type)
    if ($Type -eq 0x1000000) { return "MEM_IMAGE" }
    if ($Type -eq 0x20000) { return "MEM_PRIVATE" }
    if ($Type -eq 0x40000) { return "MEM_MAPPED" }
    return "UNKNOWN"
}

# Mapping for the -MemType flag
$TypeMapF = @{
    "Image" = 0x1000000
    "Private" = 0x20000
    "Mapped" = 0x40000
}

$SearchList = @()
if ($SearchString) { $SearchList += $SearchString }
if ($StringsFile -and (Test-Path $StringsFile)) {
    $SearchList += Get-Content $StringsFile | Where-Object { $_ -ne "" }
}

try {
    $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    Write-Log "=== PowerShell Process Memory Reader ==="
    Write-Log "Process Name: $($proc.ProcessName) (PID: $($proc.Id))"
    Write-Log "Working Set: $([Math]::Round($proc.WorkingSet64 / 1MB, 2)) MB"
    Write-Host "Filter Mode: $MemType"
    Write-Host "Search Terms: $($SearchList -join ', ')"
    Write-Host "Case Sensitive: $(-not $CaseInsensitive)"
    Write-Host ""

    $processHandle = [MemoryReader]::OpenProcess(0x0410, $false, $ProcessId)
    if ($processHandle -eq [IntPtr]::Zero) { throw "Access Denied. Run as Admin." }

    Write-Log "=== Scanning Memory Regions ==="
    $address = [IntPtr]::Zero
    $mbi = New-Object MEMORY_BASIC_INFORMATION
    $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
    $regionCount = 0
    $results = @()

    while ([MemoryReader]::VirtualQueryEx($processHandle, $address, [ref]$mbi, $mbiSize) -ne 0) {
        if ($mbi.State -eq 0x1000) { # MEM_COMMIT
            $protstr = Get-ProtectionString -Protect $mbi.Protect
            $typeStr = Get-TypeString -Type $mbi.Type
            
            # Check if region matches the user's Type filter
            $showInScan = ($MemType -eq "All") -or ($mbi.Type -eq $TypeMapF[$MemType])
            
            if ($showInScan) {
                $regionCount++
                $regionInfo = "Region {0}: 0x{1:X12} - Size: {2:N0} KB - Prot: {3} - Type: {4}" -f $regionCount, $mbi.BaseAddress.ToInt64(), ($mbi.RegionSize.ToInt64() / 1KB), $protstr, $typeStr
                Write-Host $regionInfo

                if ($SearchList.Count -gt 0 -and ($mbi.Protect -band 0x6F)) { # Readable protections
                    $bufSize = $mbi.RegionSize.ToInt64()
                    $buffer = New-Object byte[] $bufSize
                    $read = [IntPtr]::Zero
                    
                    if ([MemoryReader]::ReadProcessMemory($processHandle, $mbi.BaseAddress, $buffer, [int]$bufSize, [ref]$read)) {
                        foreach ($enc in @("Unicode", "UTF8", "ASCII", "BigEndianUnicode")) {
                            $text = [System.Text.Encoding]::($enc).GetString($buffer)
                            foreach ( $searchItem in $SearchList ) {
                                $pos = if ($CaseInsensitive) {
                                    $text.IndexOf($searchItem, [StringComparison]::OrdinalIgnoreCase)
                                } else {
                                    $text.IndexOf($searchItem)
                                }
                                if ($pos -ge 0) {
                                    $charSize = if ($enc -match 'Unicode') { 2 } else { 1 } 
                                    $searchAddr = "0x$($($mbi.BaseAddress.ToInt64() + ($pos * $charSize)).ToString("X12"))"
                                    $snippet = $text.Substring([Math]::Max(0, $pos-20), [Math]::Min(60, $text.Length-$pos)) -replace "[`r`n`t@]", " "
                                    
                                    $searchInfo = "[!] MATCH: $searchItem AT $searchAddr ($enc) Context: $snippet"
                                    Write-Host $searchInfo -ForegroundColor Green
                                    if ($OutputFile) { $results += "Region: $searchAddr, Match: $searchItem, Encoding: $enc, Context: $snippet | $searchInfo" }
                                }
                            }
                        }
                    }
                }
            }    
        }
        $address = [IntPtr]($mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64())
        if ($address.ToInt64() -lt 0) { break }
    }
    
    if ($OutputFile -and $results.Count -gt 0) {
        $results | Out-File -FilePath $OutputFile
        Write-Log "Results written to $OutputFile"
    }
    [MemoryReader]::CloseHandle($processHandle) | Out-Null
    Write-Log "Scan complete. Regions matching filter: $regionCount"
} catch { Write-Log "Error: $($_.Exception.Message)" }
