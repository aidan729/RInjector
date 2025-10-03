# RInjector - Advanced DLL Injector

A powerful, modern DLL injector written in Rust with a sleek graphical user interface. RInjector provides multiple injection techniques with a user friendly interface for security researchers, reverse engineers, and developers.


![image](https://github.com/user-attachments/assets/0dfaee41-a0ec-4e4e-ba86-a10851e59f09)

## Features

### Multiple Injection Methods
- **LoadLibrary Injection** - Classic and reliable injection method (With Eject Option)
- **NtCreateThreadEx** - Advanced kernel level thread creation
- **Manual Map Injection** - Stealthy injection bypassing PEB module lists
- **Thread Hijacking** - Context manipulation for stealth injection
- **AtomBombing** - APC based injection using global atom tables for stealth

### Modern UI
- **Dark Theme Interface** - Professional, eye friendly design
- **Real time Process Monitoring** - Live process list with search functionality
- **Activity Logging** - Color coded logs with detailed injection status
- **Drag & Drop Support** - Easy DLL management
- **Responsive Design** - Resizable panels and adaptive layout

### Advanced Capabilities
- **Multi DLL Injection** - Inject multiple DLLs simultaneously
- **Persistent Configuration** - DLL paths saved between sessions
- **Process Filtering** - Quick search and filter processes
- **Injection Validation** - Automatic DLL path validation
- **Error Handling** - Comprehensive error reporting and recovery
- **Debug Privilege Management** - Automatic elevation for system processes

## Technical Architecture

### Core Modules

#### `injector_core/`
- **`injector.rs`** - Main injection engine with trait implementations
- **`process.rs`** - Process management and enumeration
- **`winapi.rs`** - Windows API bindings and type definitions
- **`inject_helper.rs`** - PE structures and helper functions
- **`elevate.rs`** - Privilege escalation utilities
- **`utils.rs`** - Common utility functions
- **`error.rs`** - Error handling and reporting

#### Injection Techniques

**LoadLibrary Injection**
```rust
// Standard Windows DLL injection using LoadLibraryW
VirtualAllocEx() -> WriteProcessMemory() -> CreateRemoteThread()
```

**NtCreateThreadEx**
```rust
// Advanced injection using undocumented NT APIs
NtCreateThreadEx() with custom thread attributes
```

**Manual Map Injection**
```rust
// Stealthy injection without Windows loader
PE parsing -> Section mapping -> Relocation -> Import resolution -> DllMain execution
```

**Thread Hijacking**
```rust
// Context manipulation injection
SuspendThread() -> GetThreadContext() -> Shellcode injection -> SetThreadContext()
```

**AtomBombing**
```rust
// APC based injection using atom tables
Find alertable thread -> Allocate memory -> Write via atoms/APC -> QueueUserAPC() -> Execute
```

### UI Framework
- **egui** - Immediate mode GUI framework
- **eframe** - Native window management
- **Custom styling** - Modern dark theme with accent colors

## Prerequisites

- **Rust 1.70+** - Latest stable Rust compiler
- **Windows 10/11** - Target platform (x64 recommended)
- **Administrator privileges** - Required for system process injection

### Dependencies
```toml
[dependencies]
eframe = "0.30.0"
egui = "0.30.0"
rfd = "0.15.2"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
winapi = { version = "0.3.9", features = [
    "memoryapi", "minwindef", "ntdef", "winuser", "tlhelp32",
    "errhandlingapi", "psapi", "securitybaseapi", "libloaderapi",
    "synchapi", "wow64apiset", "processthreadsapi", "handleapi", "winbase"
]}
```

## Installation & Usage

### Building from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/RInjector.git
cd RInjector

# Build release version
cargo build --release

# Run the application
cargo run --release
```

## Architecture Details

### Process Management
```rust
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub handle: ProcessHandle,
}
```

### Injection Interface
```rust
pub trait Injector {
    fn inject_with_method(&self, dll_path: &str, method: InjectionMethod) -> Result<(), io::Error>;
    fn eject(&self, dll_path: &str) -> Result<(), io::Error>;
}
```

## Troubleshooting

### Common Issues

**"Access Denied" Errors**
- Run as Administrator
- Check target process security level
- Verify debug privileges

**DLL Load Failures**
- Validate DLL architecture (x86 vs x64)
- Check DLL dependencies
- Verify file permissions

**Process Not Found**
- Refresh process list
- Check process name spelling
- Ensure process is still running

**Injection Method Failures**
- Try different injection methods
- Check target process protections
- Verify Windows version compatibility

### Debug Tips
- Enable detailed logging in debug builds
- Use Process Monitor for file/registry access
- Check Windows Event Logs for system errors
- Test with simple test DLLs first

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** - `git checkout -b feature/amazing-feature`
3. **Follow Rust conventions** - Use `cargo fmt` and `cargo clippy`
4. **Add tests** - Ensure new features are tested
5. **Update documentation** - Keep README and comments current
6. **Submit a pull request** - Provide clear description of changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Legal Disclaimer

This software is provided for educational and research purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations. The authors assume no liability for misuse of this software.

## Configuration

RInjector automatically saves your DLL list to `injector_config.json` in the executable directory. This allows DLL paths to persist between sessions, so you don't need to re add them every time.

## Project Statistics

- **Language**: Rust
- **Lines of Code**: ~2,000+
- **Injection Methods**: 5
- **UI Framework**: egui
- **Platform**: Windows x64
- **License**: MIT

---

**Built with Rust** | **For Security Research & Education**