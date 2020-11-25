# memexec

[![](https://img.shields.io/crates/v/memexec)](https://crates.io/crates/memexec) [![](https://img.shields.io/crates/d/memexec?label=downloads%40crates.io&style=social)](https://crates.io/crates/memexec)

A library for loading and executing PE (Portable Executable) from memory without ever touching the disk

# Features

+ Applicable to EXE and DLL (except .NET assembly)
+ Cross-architecture, applicable to x86 and x86-64
+ Zero-dependency
+ Contains a simple, zero-copy PE parser submodule
+ Provides an IAT hooking interface

# Install

```toml
# Cargo.toml

[dependencies]
memexec = "0.2"
```

# Usage

## Execute from memory

**⚠The architecture of target program must be same as current process, otherwise an error will occur**

```rust
use memexec;
use std::fs::File;
use std::io::Read;

/***********************************************************/
/*                         EXE                             */
/***********************************************************/
let mut buf = Vec::new();
File::open("./test.exe")
    .unwrap()
    .read_to_end(&mut buf)
    .unwrap();

unsafe {
    // If you need to pass command line parameters,
    // try to modify PEB's command line buffer
    // Or use `memexec_exe_with_hooks` to hook related functions (see below)
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

## IAT hooking

Add the `hook` feature in `Cargo.toml`

```toml
[dependencies]
memexec = { version="0.2", features=[ "hook" ] }
```

Hook the `__wgetmainargs` function (see `example/hook.rs`)

```rust
let mut buf = Vec::new();
File::open("./test.x64.exe")
    .unwrap()
    .read_to_end(&mut buf)
    .unwrap();

let mut hooks = HashMap::new();

unsafe {
    hooks.insert(
        "msvcrt.dll!__wgetmainargs".into(),
        mem::transmute::<
            extern "win64" fn(
                *mut i32,
                *mut *const *const u16,
                *const c_void,
                i32,
                *const c_void,
            ) -> i32,
            *const c_void,
        >(__wgetmainargs),
    );
    memexec::memexec_exe_with_hooks(&buf, &hooks).unwrap();
}
```

The definition of `__wgetmainargs` (notice the calling convention on different archtectures):

```rust
// https://docs.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs?view=msvc-160
/*
int __wgetmainargs (
   int *_Argc,
   wchar_t ***_Argv,
   wchar_t ***_Env,
   int _DoWildCard,
   _startupinfo * _StartInfo)
*/
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
extern "win64" fn __wgetmainargs(
    _Argc: *mut i32,
    _Argv: *mut *const *const u16,
    _Env: *const c_void,
    _DoWildCard: i32,
    _StartInfo: *const c_void,
) -> i32 {
    unsafe {
        *_Argc = 2;
        let a0: Vec<_> = "program_name\0"
            .chars()
            .map(|c| (c as u16).to_le())
            .collect();
        let a1: Vec<_> = "token::whoami\0"
            .chars()
            .map(|c| (c as u16).to_le())
            .collect();
        *_Argv = [a0.as_ptr(), a1.as_ptr()].as_ptr();

        // Avoid calling destructor
        mem::forget(a0);
        mem::forget(a1);
    }

    0
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

# TODO

- [ ] Replace `LoadLibrary` with calling `load_pe_into_mem` recursively

- [ ] Replace `GetProcAddress` with self-implemented [`LdrpSnapThunk`](https://doxygen.reactos.org/dd/d83/ntdllp_8h.html#ae2196bc7f46cc2a92d36b7c4881ee633), so as to support resolving proc address by `IMAGE_IMPORT_BY_NAME.Hint`

# License

The GPLv3 license
