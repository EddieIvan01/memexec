# memexec

[![](https://img.shields.io/crates/v/memexec)](https://crates.io/crates/memexec) [![](https://img.shields.io/crates/d/memexec?label=downloads%40crates.io&style=social)](https://crates.io/crates/memexec)

Lib used to load and execute PE (Portable Executable) in memory without ever touching the disk

# Features

+ Applicable to EXE and DLL
+ Cross-architecture, applicable to x86 and x86_64
+ Zero-dependency
+ Contains a zero-copy submodule of PE parser

# Install

```
cargo install memexec
```

# Usage

## Load and execute

**⚠The architecture of target program must be same as current process, otherwise an error will occur**

```rust
use memexec;
use std::fs::File;
use std::io::Read;

/***********************************************************/
/*                         EXE                             */
/***********************************************************/
let mut buf = Vec::new();
File::open("./mimikatz.exe")
    .unwrap()
    .read_to_end(&mut buf)
    .unwrap();

unsafe {
    // If you need to pass command line parameters,
    // try to modify PEB's command line buffer
    memexec::memexec_exe(&buf).unwrap();
}


/***********************************************************/
/*                         DLL                             */
/***********************************************************/
let mut buf = Vec::new();
File::open("./test.dll")
    .unwrap()
    .read_to_end(&mut buf)
    .unwrap();

use memexec::peloader::def::DLL_PROCESS_ATTACH;
unsafe {
    // DLL's entry point is DllMain
    memexec_dll(&buf, 0 as _, DLL_PROCESS_ATTACH, 0 as _).unwrap();
}
```

## Parse PE

**PE parser could parse programs which have different architectures from current process**

```rust
use memexec::peparser::PE;

// Zero copy
// Make sure that the lifetime of `buf` is longer than `pe`
let pe = PE::new(&buf);
println!("{:?}", pe);
```

# License

The GPLv3 license
