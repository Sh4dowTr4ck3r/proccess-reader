# Process Memory Reader - PowerShell Version
# Usage: .\reader.ps1 -ProcessId <PID> [-SearchString "text"] [-AutoScan] [-ShowMemoryInfo]

param(
    [Parameter(Mandatory=$true)]
    [int]$ProcessId,
    
    [string]$SearchString = "",
    
    [switch]$AutoScan,
    
    [switch]$ShowMemoryInfo,
    
    [string]$StringsFile = "strings.txt"
)

# Global cancellation flag
$script:CancelRequested = $false

function Test-CancellationRequested {
    # Check for PowerShell's built-in cancellation
    try {
        # This will throw if Ctrl+C was pressed
        [System.Threading.Thread]::Sleep(0)
        return $false
    } catch [System.OperationCanceledException] {
        Write-Log "Scan cancelled by user (Ctrl+C)"
        return $true
    } catch {
        return $false
    }
}

# Add required Windows API functions
Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Text;

    public class MemoryReader {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_FREE = 0x10000;
        public const uint MEM_RESERVE = 0x2000;
        
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_WRITECOPY = 0x08;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOCACHE = 0x200;
        public const uint PAGE_WRITECOMBINE = 0x400;
        
        public const uint MEM_IMAGE = 0x1000000;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint MEM_MAPPED = 0x40000;
    }
"@

function Write-Log {
    param([string]$Message)
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

function Get-ProtectionString {
    param([uint32]$Protect)
    
    $baseProtect = $Protect -band 0xFF
    $result = switch ($baseProtect) {
        ([MemoryReader]::PAGE_READWRITE) { "READ/WRITE" }
        ([MemoryReader]::PAGE_READONLY) { "READ_ONLY" }
        ([MemoryReader]::PAGE_EXECUTE_READ) { "EXECUTE_READ" }
        ([MemoryReader]::PAGE_EXECUTE_READWRITE) { "EXECUTE_READWRITE" }
        ([MemoryReader]::PAGE_EXECUTE) { "EXECUTE_ONLY" }
        ([MemoryReader]::PAGE_WRITECOPY) { "WRITE_COPY" }
        ([MemoryReader]::PAGE_NOACCESS) { "NO_ACCESS" }
        default { "OTHER (0x{0:X})" -f $Protect }
    }
    
    if ($Protect -band [MemoryReader]::PAGE_GUARD) { $result += " +GUARD" }
    if ($Protect -band [MemoryReader]::PAGE_NOCACHE) { $result += " +NOCACHE" }
    if ($Protect -band [MemoryReader]::PAGE_WRITECOMBINE) { $result += " +WRITECOMBINE" }
    
    return $result
}

function Get-MemoryTypeString {
    param([uint32]$Type)
    
    switch ($Type) {
        ([MemoryReader]::MEM_IMAGE) { return "IMAGE (Program/DLL)" }
        ([MemoryReader]::MEM_PRIVATE) { return "PRIVATE (Your data)" }
        ([MemoryReader]::MEM_MAPPED) { return "MAPPED (File)" }
        default { return "UNKNOWN ($Type)" }
    }
}

function Open-ProcessForReading {
    param([int]$ProcessID)
    
    Write-Log "Opening process $ProcessID for memory reading..."
    
    $processAccess = [MemoryReader]::PROCESS_VM_READ -bor [MemoryReader]::PROCESS_QUERY_INFORMATION
    $processHandle = [MemoryReader]::OpenProcess($processAccess, $false, $ProcessID)
    
    if ($processHandle -eq [IntPtr]::Zero) {
        $error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "Error: Could not open process $ProcessID (Error code: $error)"
        Write-Log "Make sure you have sufficient privileges and the process exists."
        return $null
    }
    
    Write-Log "Successfully opened process $ProcessID"
    return $processHandle
}

function Read-ProcessMemory {
    param(
        [IntPtr]$ProcessHandle,
        [IntPtr]$Address,
        [int]$Size
    )
    
    $buffer = New-Object byte[] $Size
    $bytesRead = [IntPtr]::Zero
    
    $success = [MemoryReader]::ReadProcessMemory($ProcessHandle, $Address, $buffer, $Size, [ref]$bytesRead)
    
    if ($success) {
        return @{
            Success = $true
            Data = $buffer
            BytesRead = $bytesRead.ToInt32()
        }
    } else {
        return @{
            Success = $false
            Data = $null
            BytesRead = 0
        }
    }
}

function Get-MemoryRegions {
    param([IntPtr]$ProcessHandle)
    
    Write-Log "=== Scanning Memory Regions ==="
    
    $regions = @()
    $address = [IntPtr]::Zero
    $mbi = New-Object MemoryReader+MEMORY_BASIC_INFORMATION
    $regionCount = 0
    $totalSize = 0
    
    while ([MemoryReader]::VirtualQueryEx($ProcessHandle, $address, [ref]$mbi, [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)) -ne 0) {
        # Check for cancellation
        if (Test-CancellationRequested) {
            Write-Log "Memory region scan cancelled"
            break
        }
        
        if ($mbi.State -eq [MemoryReader]::MEM_COMMIT) {
            $regionCount++
            $totalSize += $mbi.RegionSize.ToInt64()
            
            $region = [PSCustomObject]@{
                BaseAddress = $mbi.BaseAddress
                Size = $mbi.RegionSize.ToInt64()
                Protection = $mbi.Protect
                Type = $mbi.Type
                IsReadable = ($mbi.Protect -band ([MemoryReader]::PAGE_READONLY -bor [MemoryReader]::PAGE_READWRITE -bor [MemoryReader]::PAGE_EXECUTE_READ -bor [MemoryReader]::PAGE_EXECUTE_READWRITE)) -and
                            -not ($mbi.Protect -band ([MemoryReader]::PAGE_GUARD -bor [MemoryReader]::PAGE_NOACCESS))
            }
            
            $regions += $region
            
            if ($regionCount -le 15) {
                $sizeKB = $region.Size / 1024
                $protectionStr = Get-ProtectionString -Protect $region.Protection
                $typeStr = Get-MemoryTypeString -Type $region.Type
                
                Write-Host ("Region {0}: 0x{1:X8} - Size: {2:N0} KB - Protection: {3} - Type: {4}" -f 
                    $regionCount, $region.BaseAddress.ToInt64(), $sizeKB, $protectionStr, $typeStr)
            }
        }
        
        $address = [IntPtr]($mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64())
    }
    
    Write-Log "Total readable regions: $regionCount"
    Write-Log "Total readable memory: $([Math]::Round($totalSize / 1024 / 1024, 2)) MB"
    
    return $regions
}

function Show-Context {
    param(
        [byte[]]$Buffer,
        [int]$Position,
        [string]$Encoding = "ASCII"
    )
    
    $contextStart = [Math]::Max(0, $Position - 32)
    $contextEnd = [Math]::Min($Position + 64, $Buffer.Length)
    
    $contextStr = ""
    for ($i = $contextStart; $i -lt $contextEnd; $i++) {
        $byte = $Buffer[$i]
        if ($byte -ge 32 -and $byte -le 126) {
            $contextStr += [char]$byte
        } else {
            $contextStr += "."
        }
    }
    
    Write-Host "  Context ($Encoding): $contextStr"
}

function Search-MemoryForString {
    param(
        [IntPtr]$ProcessHandle,
        [PSCustomObject[]]$MemoryRegions,
        [string]$SearchString
    )
    
    Write-Log "=== Searching for: `"$SearchString`" ==="
    
    $results = @()
    $searchBytes = [System.Text.Encoding]::ASCII.GetBytes($SearchString)
    
    foreach ($region in $MemoryRegions) {
        # Check for cancellation
        if (Test-CancellationRequested) {
            Write-Log "String search cancelled"
            break
        }
        
        if (-not $region.IsReadable -or $region.Size -gt 0x50000) { # Skip large regions (>320KB)
            continue
        }
        
        # Progress indicator for larger scans
        if ($MemoryRegions.Count -gt 50) {
            $regionIndex = [array]::IndexOf($MemoryRegions, $region)
            if ($regionIndex % 20 -eq 0) {
                Write-Host "  Progress: Region $regionIndex of $($MemoryRegions.Count)" -ForegroundColor Gray
            }
        }
        
        $memResult = Read-ProcessMemory -ProcessHandle $ProcessHandle -Address $region.BaseAddress -Size $region.Size
        
        if ($memResult.Success) {
            $buffer = $memResult.Data
            
            # Search for ASCII string
            for ($i = 0; $i -le ($buffer.Length - $searchBytes.Length); $i++) {
                $match = $true
                for ($j = 0; $j -lt $searchBytes.Length; $j++) {
                    if ($buffer[$i + $j] -ne $searchBytes[$j]) {
                        $match = $false
                        break
                    }
                }
                
                if ($match) {
                    $foundAddress = [IntPtr]($region.BaseAddress.ToInt64() + $i)
                    $results += $foundAddress
                    
                    Write-Host ("Found ASCII at: 0x{0:X8}" -f $foundAddress.ToInt64()) -ForegroundColor Green
                    Show-Context -Buffer $buffer -Position $i -Encoding "ASCII"
                }
            }
        }
    }
    
    if ($results.Count -eq 0) {
        Write-Log "String not found in process memory."
    } else {
        Write-Log "Found $($results.Count) matches total."
    }
    
    return $results
}

function Invoke-PatternScan {
    param(
        [IntPtr]$ProcessHandle,
        [PSCustomObject[]]$MemoryRegions,
        [string[]]$SearchPatterns
    )
    
    Write-Log "=== Pattern Scanning ==="
    Write-Log "Scanning for $($SearchPatterns.Count) patterns..."
    
    $totalMatches = 0
    $patternsFound = 0
    $currentPattern = 0
    
    foreach ($pattern in $SearchPatterns) {
        # Check for cancellation
        if (Test-CancellationRequested) {
            Write-Log "Pattern scan cancelled at pattern $currentPattern of $($SearchPatterns.Count)"
            break
        }
        
        $currentPattern++
        Write-Host "[$currentPattern/$($SearchPatterns.Count)] Searching for pattern: '$pattern'" -ForegroundColor Cyan
        $results = Search-MemoryForString -ProcessHandle $ProcessHandle -MemoryRegions $MemoryRegions -SearchString $pattern
        
        if ($results.Count -gt 0) {
            $patternsFound++
            $totalMatches += $results.Count
            Write-Host "✓ Pattern '$pattern': $($results.Count) matches" -ForegroundColor Green
        } else {
            Write-Host "  Pattern '$pattern': No matches" -ForegroundColor Gray
        }
    }
    
    Write-Log "=== Scan Summary ==="
    Write-Log "Patterns with matches: $patternsFound / $($SearchPatterns.Count)"
    Write-Log "Total matches found: $totalMatches"
}

function Get-SearchStrings {
    param([string]$StringsFile)
    
    $strings = @()
    
    if (Test-Path $StringsFile) {
        Write-Log "Loading search strings from: $StringsFile"
        $content = Get-Content $StringsFile -ErrorAction SilentlyContinue
        
        foreach ($line in $content) {
            $line = $line.Trim()
            # Skip empty lines and comments
            if ($line -and -not $line.StartsWith('#')) {
                $strings += $line
            }
        }
        
        Write-Log "Loaded $($strings.Count) search patterns from file"
    } else {
        Write-Log "Strings file not found: $StringsFile - using default patterns"
        # Fallback to hardcoded patterns
        $strings = @("password", "SECRET", "admin", "config", "debug", "error", "http://", "https://")
    }
    
    return $strings
}

function Show-ProcessInfo {
    param([int]$ProcessID)
    
    try {
        $process = Get-Process -Id $ProcessID -ErrorAction Stop
        Write-Log "=== Process Information ==="
        Write-Log "Process Name: $($process.ProcessName)"
        Write-Log "Process ID: $($process.Id)"
        Write-Log "Main Window Title: $($process.MainWindowTitle)"
        Write-Log "Working Set: $([Math]::Round($process.WorkingSet / 1MB, 2)) MB"
        Write-Log "Virtual Memory: $([Math]::Round($process.VirtualMemorySize / 1MB, 2)) MB"
        Write-Log "Start Time: $($process.StartTime)"
        Write-Log ""
    } catch {
        Write-Log "Could not retrieve process information: $($_.Exception.Message)"
    }
}

# Main execution
try {
    Write-Log "=== PowerShell Process Memory Reader ==="
    Write-Log "Target Process ID: $ProcessId"
    
    # Show process info
    Show-ProcessInfo -ProcessID $ProcessId
    
    # Open process for reading
    $processHandle = Open-ProcessForReading -ProcessID $ProcessId
    if (-not $processHandle) {
        exit 1
    }
    
    try {
        # Get memory regions
        $memoryRegions = Get-MemoryRegions -ProcessHandle $processHandle
        
        if ($ShowMemoryInfo) {
            Write-Log "Memory region scan completed."
            return
        }
        
        # Handle different modes
        if ($SearchString) {
            # Search for specific string
            $results = Search-MemoryForString -ProcessHandle $processHandle -MemoryRegions $memoryRegions -SearchString $SearchString
            Write-Log "Search completed. Found $($results.Count) matches."
            
        } elseif ($AutoScan) {
            # Auto-scan for patterns from strings file
            $searchStrings = Get-SearchStrings -StringsFile $StringsFile
            Invoke-PatternScan -ProcessHandle $processHandle -MemoryRegions $memoryRegions -SearchPatterns $searchStrings
            
        } else {
            # Default: show basic info and limited patterns
            $defaultStrings = @("password", "admin", "secret", "debug", "error")
            Invoke-PatternScan -ProcessHandle $processHandle -MemoryRegions $memoryRegions -SearchPatterns $defaultStrings
            Write-Log "Use -AutoScan for comprehensive scan with all patterns or -SearchString 'text' to search for specific text."
        }
        
    } finally {
        # Cleanup
        [void][MemoryReader]::CloseHandle($processHandle)
        Write-Log "Process handle closed."
    }
    
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}

Write-Log "Done!"