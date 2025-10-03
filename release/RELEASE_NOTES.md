# RInjector v1.0.0 - Release Notes

## What's New

### New Injection Method
- **AtomBombing** - APC-based injection technique using global atom tables for stealthy DLL injection

### New Features
- **Persistent Configuration** - DLL paths are now automatically saved and loaded between sessions
- **Enhanced Process Detection** - Improved process enumeration and filtering
- **Comprehensive Verification** - Added validation for shellcode, function pointers, and DLL paths

### Bug Fixes
- Fixed AtomBombing shellcode jump offset calculation
- Fixed pointer arithmetic issues in memory allocation
- Removed UNC path prefix that caused LoadLibraryA failures
- Fixed stack alignment in shellcode execution

## Supported Injection Methods

1. **LoadLibrary** - Classic injection with eject support
2. **NtCreateThreadEx** - Advanced kernel-level thread creation
3. **Manual Map** - Stealthy injection bypassing module lists
4. **Thread Hijacking** - Context manipulation injection
5. **AtomBombing** - APC-based stealth injection

## Installation

1. Extract `RInjector.exe` to any location
2. Run as Administrator (required for most injection scenarios)
3. Add DLLs and select target process
4. Choose injection method and inject

## System Requirements

- **OS**: Windows 10/11 (x64)
- **Privileges**: Administrator rights recommended
- **Architecture**: 64-bit

## Notes

- DLL architecture must match target process (x86/x64)
- Some injection methods may be blocked by security software
- For best results with AtomBombing, use minimal DLLs without heavy dependencies
- Configuration file (`injector_config.json`) stores your DLL list

## Support

For issues, questions, or contributions, visit the GitHub repository.

**Disclaimer**: This tool is for educational and research purposes only. Use responsibly.
