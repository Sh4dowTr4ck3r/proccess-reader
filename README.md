# Process Memory Reader

Advanced PowerShell tool for reading and analyzing process memory in real-time.

## Overview

This tool provides comprehensive process memory analysis capabilities using Windows API calls through PowerShell. Designed for security research, malware analysis, and system debugging.

## Features

### Core Functionality
- **Process Memory Reading**: Direct memory access using Windows API
- **Memory Region Scanning**: Comprehensive memory layout analysis
- **Pattern Searching**: Advanced string and byte pattern detection
- **Real-time Analysis**: Live memory monitoring capabilities

### Technical Features
- **Windows API Integration**: Kernel32.dll function imports
- **Memory Protection Analysis**: Detailed page protection information
- **Multi-encoding Support**: ASCII, Unicode, and raw byte searching
- **Context Display**: Memory context around found patterns
- **Safe Memory Access**: Protected reading with error handling

## Usage

### Basic Process Analysis
```powershell
# Analyze process memory regions
.\reader.ps1 -ProcessId 1234 -ShowMemoryInfo

# Search for specific string in memory
.\reader.ps1 -ProcessId 1234 -SearchString "password"

# Auto-scan using default strings file (strings.txt)
.\reader.ps1 -ProcessId 1234 -AutoScan

# Auto-scan using custom strings file
.\reader.ps1 -ProcessId 1234 -AutoScan -StringsFile "custom_patterns.txt"
```

### Advanced Analysis
```powershell
# Deep pattern scanning with comprehensive strings
.\reader.ps1 -ProcessId 1234 -SearchString "SECRET" -AutoScan

# Memory layout analysis with detailed regions
.\reader.ps1 -ProcessId 1234 -ShowMemoryInfo

# Scan Discord process for authentication patterns
.\reader.ps1 -ProcessId 1234 -AutoScan -StringsFile "strings.txt"

# Custom malware analysis patterns
.\reader.ps1 -ProcessId 1234 -AutoScan -StringsFile "malware_indicators.txt"
```

## Memory Analysis Details

### Memory Region Types
- **IMAGE**: Executable code (programs/DLLs)
- **PRIVATE**: Application data and heap
- **MAPPED**: File-backed memory regions

### Protection Levels
- **READ/WRITE**: Standard data pages
- **READ_ONLY**: Constants and read-only data
- **EXECUTE_READ**: Code sections
- **EXECUTE_READWRITE**: Self-modifying code
- **NO_ACCESS**: Protected/guarded pages

### Pattern Detection
- **ASCII String Search**: Standard text pattern matching
- **Context Analysis**: Memory context around matches
- **Multiple Pattern Scanning**: Automated scanning with configurable patterns
- **Address Resolution**: Exact memory location reporting
- **Progress Tracking**: Real-time scanning progress for large pattern sets

## Strings File Configuration

### Default Patterns (strings.txt)
The tool includes 120+ predefined patterns covering:
- **Credentials**: password, admin, secret, token, api_key
- **Network**: http://, https://, localhost, IP addresses
- **System**: Windows paths, registry keys, system32
- **Crypto**: RSA, AES, SHA256, encryption keywords
- **Development**: malloc, debug, error, configuration
- **Malware Indicators**: keylog, inject, payload, backdoor

### Custom Pattern Files
```txt
# Format: one pattern per line
# Lines starting with # are comments
password
Secret_API_Key
https://api.example.com
C:\\sensitive_data
# Add your custom patterns here
```

### Performance Optimization
- **Region Filtering**: Skips non-readable and oversized memory regions
- **Progress Indicators**: Shows scanning progress for large processes
- **Memory Limits**: Optimized for regions under 320KB for speed
- **Cancellation Support**: Graceful exit on interruption

## Security Features

### Safe Memory Access
- **Privilege Checking**: Validates process access rights
- **Error Handling**: Graceful failure on access violations
- **Resource Management**: Proper handle cleanup
- **Memory Bounds**: Protected memory region validation

### Process Security
- **Read-only Access**: No memory modification capabilities
- **Process Isolation**: Respects system security boundaries
- **Audit Trail**: Comprehensive logging of all operations

## Files

### `reader.ps1`
Main PowerShell memory analysis tool with Windows API integration.

### `strings.txt`
Comprehensive pattern database containing 120+ search strings organized by category:
- Authentication and credentials patterns
- Network and communication identifiers  
- System paths and registry locations
- Cryptographic function names
- Development and debugging strings
- Malware behavior indicators

## Requirements

- **PowerShell**: 5.1+ or PowerShell 7+
- **Windows**: Windows 10/11 or Windows Server
- **Privileges**: Sufficient rights to access target processes
- **.NET Framework**: 4.5+ for API interop
