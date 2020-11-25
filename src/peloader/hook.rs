#![cfg(feature = "hook")]

use std::hash::Hash;
use std::mem;

#[derive(Debug)]
pub enum Thunk<'a> {
    Ordinal(isize),
    Name(&'a str),
}

impl<'a> PartialEq for Thunk<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (&Thunk::Ordinal(s), &Thunk::Ordinal(o)) => s == o,
            (&Thunk::Name(s), &Thunk::Name(o)) => s == o,
            _ => false,
        }
    }
}

impl<'a> Eq for Thunk<'a> {}

impl<'a> Hash for Thunk<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);
        match *self {
            Thunk::Ordinal(o) => o.hash(state),
            Thunk::Name(n) => n.hash(state),
        };
    }
}

#[derive(Debug)]
pub struct ProcDesc<'a> {
    // Use `String` instead of `&str`,
    // because we need a case conversion in `new` function
    dll: String,
    thunk: Thunk<'a>,
}

impl<'a> PartialEq for ProcDesc<'a> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.dll == other.dll && self.thunk == other.thunk
    }
}

impl<'a> Eq for ProcDesc<'a> {}

impl<'a> Hash for ProcDesc<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.dll.hash(state);
        self.thunk.hash(state);
    }
}

impl<'a> ProcDesc<'a> {
    /// Dll name is case insensitive
    pub fn new(dll: &str, thunk: Thunk<'a>) -> ProcDesc<'a> {
        ProcDesc {
            dll: dll.to_ascii_lowercase(),
            thunk: thunk,
        }
    }
}

// Couldn't implement `FromStr` trait here,
// because the signature of `from_str` doesn't allow an explicit lifetime hint
impl<'a> From<&'a str> for ProcDesc<'a> {
    fn from(s: &'a str) -> Self {
        match s.find('!') {
            Some(i) => {
                let (dll, proc_name) = s.split_at(i);
                ProcDesc {
                    dll: dll.to_ascii_lowercase(),
                    thunk: Thunk::Name(&proc_name[1..]),
                }
            }
            None => match s.find('#') {
                Some(i) => {
                    let (dll, proc_ord) = s.split_at(i);
                    ProcDesc {
                        dll: dll.to_ascii_lowercase(),
                        thunk: Thunk::Ordinal(proc_ord[1..].parse().unwrap_or(0)),
                    }
                }
                // Failure case
                None => ProcDesc {
                    dll: String::new(),
                    thunk: Thunk::Ordinal(0),
                },
            },
        }
    }
}

/*
use std::collections::HashMap;
use std::os::raw::c_void;

trait ProcDescTbl<'a> {
    fn get(&self, proc_desc: &'a ProcDesc) -> Option<&*const c_void>;
}

impl<'a> ProcDescTbl<'a> for HashMap<ProcDesc<'a>, *const c_void> {
    fn get(&self, proc_desc: &'a ProcDesc) -> Option<&*const c_void> {
        self.get(proc_desc)
    }
}
*/

/*
// Implement FNV-1a hash
#[derive(Debug, Hash)]
pub struct ProcHash(u64, u64);

impl PartialEq for ProcHash {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl Eq for ProcHash {}

impl ProcHash {
    /// Dll name is case insensitive
    /// ProcHash::new("kernel32.dll", Thunk::Name("CreateProcessW"))
    pub fn new(dll: &str, thunk: Thunk) -> ProcHash {
        // The hash of DLL and thunk is calculated and saved separately,
        // in order to reduce the collision probability
        let mut h1: u64 = 0xcbf29ce484222325;

        for c in dll.chars() {
            h1 ^= c.to_ascii_lowercase() as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        }

        let mut h2: u64 = 0xcbf29ce484222325;
        match thunk {
            Thunk::Ordinal(ord) => {
                // #
                h2 ^= 0x23;
                h2 = h2.wrapping_mul(0x100000001b3);
                h2 ^= ord as u64;
                h2 = h2.wrapping_mul(0x100000001b3);
            }
            Thunk::Name(name) => {
                // !
                h2 ^= 0x21;
                h2 = h2.wrapping_mul(0x100000001b3);
                for c in name.chars() {
                    h2 ^= c as u64;
                    h2 = h2.wrapping_mul(0x100000001b3);
                }
            }
        }

        ProcHash(h1, h2)
    }
}
*/
