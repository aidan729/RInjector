# GitHub Release Guide

## Steps to Create a Release

### 1. Tag Your Release
```bash
git tag -a v1.0.0 -m "Release v1.0.0 - AtomBombing support and config persistence"
git push origin v1.0.0
```

### 2. Create Release on GitHub

1. Go to your repository on GitHub
2. Click on "Releases" in the right sidebar
3. Click "Draft a new release"
4. Fill in the release form:

**Tag version**: `v1.0.0`

**Release title**: `RInjector v1.0.0 - AtomBombing & Config Persistence`

**Description**:
```markdown
## What's New in v1.0.0

### New Features
- Added AtomBombing injection method for stealthy APC-based injection
- DLL paths now persist between sessions via auto-save configuration
- Enhanced verification and debugging for all injection methods

### Improvements
- Fixed critical bugs in AtomBombing shellcode execution
- Improved memory layout and pointer arithmetic
- Better error handling and process alive detection

### Supported Injection Methods
- LoadLibrary (with Eject)
- NtCreateThreadEx
- Manual Map
- Thread Hijacking
- AtomBombing (NEW)

### Downloads
- **RInjector.exe** - Main executable (Windows x64)
- See RELEASE_NOTES.md for detailed information

### System Requirements
- Windows 10/11 (x64)
- Administrator privileges recommended

**Note**: Windows Defender or antivirus software may flag this tool. This is expected behavior for DLL injectors. Add an exception if needed.
```

5. **Attach Files**:
   - Drag and drop `release/RInjector.exe`
   - Optionally attach `release/RELEASE_NOTES.md`

6. **Pre-release**: Leave unchecked (unless this is a beta)

7. Click "Publish release"

## Creating a ZIP Archive (Optional)

If you prefer to release as a ZIP:

```bash
cd release
zip -r RInjector-v1.0.0-Windows-x64.zip RInjector.exe RELEASE_NOTES.md
```

Then upload the ZIP file to the GitHub release.

## Version Numbering

Follow semantic versioning (MAJOR.MINOR.PATCH):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

Examples:
- v1.0.0 - Initial release
- v1.1.0 - Added new injection method
- v1.1.1 - Fixed bug in existing feature
