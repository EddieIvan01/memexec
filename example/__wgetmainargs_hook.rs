use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::raw::c_void;

// https://docs.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs?view=msvc-160
/*
int __wgetmainargs (
   int *_Argc,
   wchar_t ***_Argv,
   wchar_t ***_Env,
   int _DoWildCard,
   _startupinfo * _StartInfo)
*/
#[cfg(all(target_arch = "x86", target_os = "windows"))]
extern "cdecl" fn __wgetmainargs(
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

#[cfg(all(target_arch = "x86", target_os = "windows"))]
fn hook_x86() {
    let mut buf = Vec::new();
    File::open("./test.x86.exe")
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();

    let mut hooks = HashMap::new();

    unsafe {
        hooks.insert(
            "msvcrt.dll!__wgetmainargs".into(),
            mem::transmute::<
                extern "cdecl" fn(
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
}

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

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn hook_x64() {
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
}
