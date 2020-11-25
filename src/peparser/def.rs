use std::os::raw::c_void;

pub(crate) type WORD = u16;
pub(crate) type LONG = i32;
pub(crate) type DWORD = u32;
pub(crate) type BYTE = u8;
pub(crate) type ULONGLONG = u64;
pub(crate) type CHAR = i8;
pub(crate) type PVOID = *const c_void;

pub(crate) const IMAGE_DOS_SIGNATURE: WORD = 0x5a4d;
pub(crate) const IMAGE_NT_SIGNATURE: DWORD = 0x00004550;

pub(crate) const IMAGE_FILE_EXECUTABLE_IMAGE: WORD = 0x0002; // File is executable  (i.e. no unresolved external references).
#[allow(dead_code)]
pub(crate) const IMAGE_FILE_LARGE_ADDRESS_AWARE: WORD = 0x0020; // App can handle >2gb addresses
#[allow(dead_code)]
pub(crate) const IMAGE_FILE_32BIT_MACHINE: WORD = 0x0100; // 32 bit word machine.
pub(crate) const IMAGE_FILE_DLL: WORD = 0x2000; // File is a DLL.

pub(crate) const IMAGE_FILE_MACHINE_I386: WORD = 0x014c;
pub(crate) const IMAGE_FILE_MACHINE_AMD64: WORD = 0x8664;

pub(crate) const IMAGE_NT_OPTIONAL_HDR32_MAGIC: WORD = 0x10b;
pub(crate) const IMAGE_NT_OPTIONAL_HDR64_MAGIC: WORD = 0x20b;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

pub const IMAGE_SCN_MEM_EXECUTE: DWORD = 0x20000000;
pub const IMAGE_SCN_MEM_READ: DWORD = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: DWORD = 0x80000000;

pub(crate) const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

pub(crate) const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0; // Export Directory
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1; // Import Directory
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2; // Resource Directory
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3; // Exception Directory
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4; // Security Directory
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5; // Base Relocation Table
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6; // Debug Directory
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7; // Architecture Specific Data
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8; // RVA of GP
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9; // TLS Directory
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10; // Load Configuration Directory
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11; // Bound Import Directory in headers
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12; // Import Address Table
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13; // Delay Load Import Descriptors
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14; // COM Runtime descriptor

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) const IMAGE_REL_BASED_DIR64: WORD = 10;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) const IMAGE_REL_BASED_HIGHLOW: WORD = 3;

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) const IMAGE_REL_BASED: WORD = IMAGE_REL_BASED_DIR64;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) const IMAGE_REL_BASED: WORD = IMAGE_REL_BASED_HIGHLOW;

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) const IMAGE_ORDINAL_FLAG64: isize = 0x8000000000000000;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) const IMAGE_ORDINAL_FLAG32: isize = 0x80000000;

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) const IMAGE_ORDINAL_FLAG: isize = IMAGE_ORDINAL_FLAG64;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) const IMAGE_ORDINAL_FLAG: isize = IMAGE_ORDINAL_FLAG32;

macro_rules! struct_wrapper {
    (struct $name:ident {
        $($field:ident: $t:ty,)*
    }) => {
        #[repr(C)]
        #[derive(Debug)]
        pub struct $name {
            $(pub $field: $t),*
        }
    }
}

struct_wrapper!(
    struct IMAGE_DOS_HEADER {
        // DOS .EXE header
        e_magic: WORD,      // Magic number
        e_cblp: WORD,       // Bytes on last page of file
        e_cp: WORD,         // Pages in file
        e_crlc: WORD,       // Relocations
        e_cparhdr: WORD,    // Size of header in paragraphs
        e_minalloc: WORD,   // Minimum extra paragraphs needed
        e_maxalloc: WORD,   // Maximum extra paragraphs needed
        e_ss: WORD,         // Initial (relative) SS value
        e_sp: WORD,         // Initial SP value
        e_csum: WORD,       // Checksum
        e_ip: WORD,         // Initial IP value
        e_cs: WORD,         // Initial (relative) CS value
        e_lfarlc: WORD,     // File address of relocation table
        e_ovno: WORD,       // Overlay number
        e_res: [WORD; 4],   // Reserved words
        e_oemid: WORD,      // OEM identifier (for e_oeminfo)
        e_oeminfo: WORD,    // OEM information; e_oemid specific
        e_res2: [WORD; 10], // Reserved words
        e_lfanew: LONG,     // File address of new exe header
    }
);

struct_wrapper!(
    struct IMAGE_FILE_HEADER {
        Machine: WORD,
        NumberOfSections: WORD,
        TimeDateStamp: DWORD,
        PointerToSymbolTable: DWORD,
        NumberOfSymbols: DWORD,
        SizeOfOptionalHeader: WORD,
        Characteristics: WORD,
    }
);

/*
ImageBase

EXE
  32-bit 0x400000
  64-bit 0x140000000

DLL
  32-bit 0x10000000
  64-bit 0x180000000
*/

struct_wrapper!(
    struct IMAGE_OPTIONAL_HEADER32 {
        Magic: WORD,
        MajorLinkerVersion: BYTE,
        MinorLinkerVersion: BYTE,
        SizeOfCode: DWORD,
        SizeOfInitializedData: DWORD,
        SizeOfUninitializedData: DWORD,
        AddressOfEntryPoint: DWORD,
        BaseOfCode: DWORD,
        BaseOfData: DWORD,
        ImageBase: DWORD,
        SectionAlignment: DWORD,
        FileAlignment: DWORD,
        MajorOperatingSystemVersion: WORD,
        MinorOperatingSystemVersion: WORD,
        MajorImageVersion: WORD,
        MinorImageVersion: WORD,
        MajorSubsystemVersion: WORD,
        MinorSubsystemVersion: WORD,
        Win32VersionValue: DWORD,
        SizeOfImage: DWORD,
        SizeOfHeaders: DWORD,
        CheckSum: DWORD,
        Subsystem: WORD,
        DllCharacteristics: WORD,
        SizeOfStackReserve: DWORD,
        SizeOfStackCommit: DWORD,
        SizeOfHeapReserve: DWORD,
        SizeOfHeapCommit: DWORD,
        LoaderFlags: DWORD,
        NumberOfRvaAndSizes: DWORD,
        DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
    }
);

struct_wrapper!(
    struct IMAGE_NT_HEADERS32 {
        Signature: DWORD,
        FileHeader: IMAGE_FILE_HEADER,
        OptionalHeader: IMAGE_OPTIONAL_HEADER32,
    }
);

struct_wrapper!(
    struct IMAGE_OPTIONAL_HEADER64 {
        Magic: WORD,
        MajorLinkerVersion: BYTE,
        MinorLinkerVersion: BYTE,
        SizeOfCode: DWORD,
        SizeOfInitializedData: DWORD,
        SizeOfUninitializedData: DWORD,
        AddressOfEntryPoint: DWORD,
        BaseOfCode: DWORD,
        ImageBase: ULONGLONG,
        SectionAlignment: DWORD,
        FileAlignment: DWORD,
        MajorOperatingSystemVersion: WORD,
        MinorOperatingSystemVersion: WORD,
        MajorImageVersion: WORD,
        MinorImageVersion: WORD,
        MajorSubsystemVersion: WORD,
        MinorSubsystemVersion: WORD,
        Win32VersionValue: DWORD,
        SizeOfImage: DWORD,
        SizeOfHeaders: DWORD,
        CheckSum: DWORD,
        Subsystem: WORD,
        DllCharacteristics: WORD,
        SizeOfStackReserve: ULONGLONG,
        SizeOfStackCommit: ULONGLONG,
        SizeOfHeapReserve: ULONGLONG,
        SizeOfHeapCommit: ULONGLONG,
        LoaderFlags: DWORD,
        NumberOfRvaAndSizes: DWORD,
        DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
    }
);

struct_wrapper!(
    struct IMAGE_NT_HEADERS64 {
        Signature: DWORD,
        FileHeader: IMAGE_FILE_HEADER,
        OptionalHeader: IMAGE_OPTIONAL_HEADER64,
    }
);

struct_wrapper!(
    struct IMAGE_DATA_DIRECTORY {
        VirtualAddress: DWORD,
        Size: DWORD,
    }
);

struct_wrapper!(
    struct IMAGE_SECTION_HEADER {
        Name: [u8; IMAGE_SIZEOF_SHORT_NAME],
        /*
            union {
                DWORD   PhysicalAddress;
                DWORD   VirtualSize;
            } Misc;
        */
        Misc: DWORD,
        VirtualAddress: DWORD,
        SizeOfRawData: DWORD,
        PointerToRawData: DWORD,
        PointerToRelocations: DWORD,
        PointerToLinenumbers: DWORD,
        NumberOfRelocations: WORD,
        NumberOfLinenumbers: WORD,
        Characteristics: DWORD,
    }
);

struct_wrapper!(
    struct IMAGE_BASE_RELOCATION {
        VirtualAddress: DWORD,
        SizeOfBlock: DWORD,
    }
);

struct_wrapper!(
    struct IMAGE_IMPORT_DESCRIPTOR {
        /*
        union {
            DWORD   Characteristics;            // 0 for terminating null import descriptor
            DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        }
        */
        OriginalFirstThunk: DWORD,
        // 0 if not bound,
        // -1 if bound, and real date\time stamp
        //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
        // O.W. date/time stamp of DLL bound to (Old BIND)
        TimeDateStamp: DWORD,
        ForwarderChain: DWORD, // -1 if no forwarders
        Name: DWORD,
        FirstThunk: DWORD, // RVA to IAT (if bound this IAT has actual addresses)
    }
);

/*
union {
    ULONGLONG ForwarderString;      // PBYTE
    ULONGLONG Function;             // PDWORD
    ULONGLONG Ordinal;
    ULONGLONG AddressOfData;        // PIMAGE_IMPORT_BY_NAME
}
*/
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) type IMAGE_THUNK_DATA64 = ULONGLONG;

/*
union {
    DWORD ForwarderString;      // PBYTE
    DWORD Function;             // PDWORD
    DWORD Ordinal;
    DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
}
*/
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) type IMAGE_THUNK_DATA32 = DWORD;

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) type IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) type IMAGE_THUNK_DATA = IMAGE_THUNK_DATA32;

struct_wrapper!(
    struct IMAGE_IMPORT_BY_NAME {
        Hint: WORD,
        Name: CHAR,
    }
);

pub type PIMAGE_TLS_CALLBACK = extern "system" fn(PVOID, DWORD, PVOID);

struct_wrapper!(
    struct IMAGE_TLS_DIRECTORY64 {
        StartAddressOfRawData: ULONGLONG,
        EndAddressOfRawData: ULONGLONG,
        AddressOfIndex: ULONGLONG,     // PDWORD
        AddressOfCallBacks: ULONGLONG, // PIMAGE_TLS_CALLBACK *;
        SizeOfZeroFill: DWORD,

        /*
        union {
            DWORD Characteristics;
            struct {
                DWORD Reserved0 : 20;
                DWORD Alignment : 4;
                DWORD Reserved1 : 8;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        */
        Reserved0: DWORD,
        Alignment: DWORD,
        Reserved1: DWORD,
    }
);

struct_wrapper!(
    struct IMAGE_TLS_DIRECTORY32 {
        StartAddressOfRawData: DWORD,
        EndAddressOfRawData: DWORD,
        AddressOfIndex: DWORD,     // PDWORD
        AddressOfCallBacks: DWORD, // PIMAGE_TLS_CALLBACK *;
        SizeOfZeroFill: DWORD,

        /*
        union {
            DWORD Characteristics;
            struct {
                DWORD Reserved0 : 20;
                DWORD Alignment : 4;
                DWORD Reserved1 : 8;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        */
        Reserved0: DWORD,
        Alignment: DWORD,
        Reserved1: DWORD,
    }
);

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub(crate) type IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY64;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub(crate) type IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY32;
