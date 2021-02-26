use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use goblin::elf::{
    header::{EM_386, EM_AARCH64, EM_ARM, EM_PPC64, EM_S390, EM_X86_64},
    sym::STT_FUNC,
    Elf,
};
use goblin::strtab::Strtab;
use regex::Regex;
use scroll::Pread;
use structopt::StructOpt;
use thiserror::Error;

mod policy;

/// Error raised during auditing an elf file for manylinux compatibility
#[derive(Error, Debug)]
#[error("Ensuring manylinux compliance failed")]
pub enum AuditWheelError {
    /// The wheel couldn't be read
    #[error("Failed to read the wheel")]
    IOError(#[source] io::Error),
    /// The wheel couldn't be read
    #[error("Failed to read the wheel")]
    ZipError(#[source] zip::result::ZipError),
    /// Reexports elfkit parsing errors
    #[error("Goblin failed to parse the elf file")]
    GoblinError(#[source] goblin::error::Error),
}

/// Structure of "version needed" entries is documented in
/// https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html
#[derive(Clone, Copy, Debug, Pread)]
#[repr(C)]
struct GnuVersionNeed {
    /// Version of structure. This value is currently set to 1,
    /// and will be reset if the versioning implementation is incompatibly altered.
    version: u16,
    /// Number of associated verneed array entries.
    cnt: u16,
    /// Offset to the file name string in the section header, in bytes.
    file: u32,
    /// Offset to a corresponding entry in the vernaux array, in bytes.
    aux: u32,
    /// Offset to the next verneed entry, in bytes.
    next: u32,
}

/// Version Needed Auxiliary Entries
#[derive(Clone, Copy, Debug, Pread)]
#[repr(C)]
struct GnuVersionNeedAux {
    /// Dependency name hash value (ELF hash function).
    hash: u32,
    /// Dependency information flag bitmask.
    flags: u16,
    /// Object file version identifier used in the .gnu.version symbol version array.
    /// Bit number 15 controls whether or not the object is hidden; if this bit is set,
    /// the object cannot be used and the static linker will ignore the symbol's presence in the object.
    other: u16,
    /// Offset to the dependency name string in the section header, in bytes.
    name: u32,
    /// Offset to the next vernaux entry, in bytes.
    next: u32,
}

#[derive(Clone, Debug)]
struct VersionedLibrary {
    /// library name
    name: String,
    /// versions needed
    versions: HashSet<String>,
}

/// Find required dynamic linked libraries with version information
fn find_versioned_libraries(
    elf: &Elf,
    buffer: &[u8],
) -> Result<Vec<VersionedLibrary>, AuditWheelError> {
    let mut symbols = Vec::new();
    let section = elf
        .section_headers
        .iter()
        .find(|h| &elf.shdr_strtab[h.sh_name] == ".gnu.version_r");
    if let Some(section) = section {
        let linked_section = &elf.section_headers[section.sh_link as usize];
        linked_section
            .check_size(buffer.len())
            .map_err(AuditWheelError::GoblinError)?;
        let strtab = Strtab::parse(
            buffer,
            linked_section.sh_offset as usize,
            linked_section.sh_size as usize,
            0x0,
        )
        .map_err(AuditWheelError::GoblinError)?;
        let num_versions = section.sh_info as usize;
        let mut offset = section.sh_offset as usize;
        for _ in 0..num_versions {
            let ver = buffer
                .gread::<GnuVersionNeed>(&mut offset)
                .map_err(goblin::error::Error::Scroll)
                .map_err(AuditWheelError::GoblinError)?;
            let mut versions = HashSet::new();
            for _ in 0..ver.cnt {
                let ver_aux = buffer
                    .gread::<GnuVersionNeedAux>(&mut offset)
                    .map_err(goblin::error::Error::Scroll)
                    .map_err(AuditWheelError::GoblinError)?;
                let aux_name = &strtab[ver_aux.name as usize];
                versions.insert(aux_name.to_string());
            }
            let name = &strtab[ver.file as usize];
            // Skip dynamic linker/loader
            if name.starts_with("ld-linux") || name == "ld64.so.2" || name == "ld64.so.1" {
                continue;
            }
            symbols.push(VersionedLibrary {
                name: name.to_string(),
                versions,
            });
        }
    }
    Ok(symbols)
}

/// Find incompliant symbols from symbol versions
fn find_incompliant_symbols(
    elf: &Elf,
    symbol_versions: &[String],
) -> Result<Vec<String>, AuditWheelError> {
    let mut symbols = Vec::new();
    let strtab = &elf.strtab;
    for sym in &elf.syms {
        if sym.st_type() == STT_FUNC {
            let name = strtab
                .get(sym.st_name)
                .unwrap_or(Ok("BAD NAME"))
                .map_err(AuditWheelError::GoblinError)?;
            for symbol_version in symbol_versions {
                if name.ends_with(&format!("@{}", symbol_version)) {
                    symbols.push(name.to_string());
                }
            }
        }
    }
    Ok(symbols)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Manylinux {
    Manylinux1,
    Manylinux2010,
    Manylinux2014,
    #[allow(non_camel_case_types)]
    Manylinux_2_24,
}

impl fmt::Display for Manylinux {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Manylinux::Manylinux1 => write!(f, "manylinux1"),
            Manylinux::Manylinux2010 => write!(f, "manylinux2010"),
            Manylinux::Manylinux2014 => write!(f, "manylinux2014"),
            Manylinux::Manylinux_2_24 => write!(f, "manylinux_2_24"),
        }
    }
}

impl FromStr for Manylinux {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1" | "manylinux1" => Ok(Manylinux::Manylinux1),
            "2010" | "manylinux2010" => Ok(Manylinux::Manylinux2010),
            "2014" | "manylinux2014" => Ok(Manylinux::Manylinux2014),
            "2_24" | "manylinux_2_24" => Ok(Manylinux::Manylinux_2_24),
            _ => Err("Invalid value for the manylinux option"),
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "auditwheel-symbols")]
struct Opt {
    #[structopt(
        short,
        long,
        possible_values = &["1", "2010", "2014", "2_24"],
        case_insensitive = true,
    )]
    manylinux: Option<Manylinux>,
    #[structopt(name = "FILE", parse(from_os_str))]
    path: PathBuf,
}

fn check_symbols(
    lib_name: &str,
    elf: &Elf,
    buffer: &[u8],
    arch: &str,
    manylinux: Manylinux,
) -> Result<bool, AuditWheelError> {
    let policies = crate::policy::Policy::load();
    let policy = policies
        .iter()
        .find(|p| p.name == manylinux.to_string())
        .unwrap();
    if !policy.symbol_versions.contains_key(arch) {
        eprintln!(
            "{} is not {} compliant because it has unsupported architecture {}",
            lib_name, manylinux, arch
        );
        return Ok(false);
    }
    // This returns essentially the same as ldd
    let deps: Vec<String> = elf.libraries.iter().map(ToString::to_string).collect();
    let versioned_libraries = find_versioned_libraries(&elf, &buffer)?;

    let mut offenders = HashSet::new();
    for dep in deps {
        // Skip dynamic linker/loader
        if dep.starts_with("ld-linux") || dep == "ld64.so.2" || dep == "ld64.so.1" {
            continue;
        }
        if !policy.lib_whitelist.contains(&dep) {
            offenders.insert(dep);
        }
    }
    for library in versioned_libraries {
        if !policy.lib_whitelist.contains(&library.name) {
            offenders.insert(library.name.clone());
            continue;
        }
        let mut versions: HashMap<String, HashSet<String>> = HashMap::new();
        for v in &library.versions {
            let mut parts = v.splitn(2, '_');
            let name = parts.next().unwrap();
            let version = parts.next().unwrap();
            versions
                .entry(name.to_string())
                .or_default()
                .insert(version.to_string());
        }
        let arch_versions = &policy.symbol_versions[arch];
        for (name, versions_needed) in versions.iter() {
            let versions_allowed = &arch_versions[name];
            if !versions_needed.is_subset(versions_allowed) {
                let offending_versions: Vec<&str> = versions_needed
                    .difference(versions_allowed)
                    .map(|v| v.as_ref())
                    .collect();
                let offending_symbol_versions: Vec<String> = offending_versions
                    .iter()
                    .map(|v| format!("{}_{}", name, v))
                    .collect();
                let offending_symbols = find_incompliant_symbols(&elf, &offending_symbol_versions)?;
                let offender = if offending_symbols.is_empty() {
                    format!(
                        "{}\toffending versions:  {}",
                        library.name,
                        offending_symbol_versions.join(", ")
                    )
                } else {
                    format!(
                        "{}\toffending symbols:  {}",
                        library.name,
                        offending_symbols.join(", ")
                    )
                };
                offenders.insert(offender);
            }
        }
    }

    // Checks if we can give a more helpful error message
    let is_libpython = Regex::new(r"^libpython3\.\d+\.so\.\d+\.\d+$").unwrap();
    let offenders: Vec<String> = offenders.into_iter().collect();
    match offenders.as_slice() {
        [] => eprintln!("{} is {} compliant.", lib_name, manylinux),
        [lib] if is_libpython.is_match(lib) => {
            eprintln!(
                "{} links libpython ({}), which libraries must not do.\n",
                lib_name, lib
            );
            return Ok(false);
        }
        offenders => {
            eprintln!(
                "{} is not {} compliant because it links the following forbidden libraries:",
                lib_name, manylinux
            );
            for offender in offenders {
                eprintln!("{}", offender);
            }
            return Ok(false);
        }
    }
    Ok(true)
}

fn main() -> Result<(), AuditWheelError> {
    let opt = Opt::from_args();
    let filename = opt
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("Failed to get wheel filename");
    let wheel_type = filename
        .rsplitn(2, '-')
        .next()
        .expect("Failed to get wheel type");
    let mut parts = wheel_type.splitn(2, '_');
    let platform = parts.next().expect("Failed to get wheel platform");
    let manylinux = opt.manylinux.unwrap_or_else(|| {
        if let Ok(manylinux) = platform.parse::<Manylinux>() {
            manylinux
        } else {
            eprintln!(
                "Cannot infer manylinux version from `{}`, please specify `--manylinux` argument",
                platform
            );
            process::exit(1);
        }
    });
    let mut compliant = true;
    let wheel = fs_err::File::open(&opt.path).map_err(AuditWheelError::IOError)?;
    if let Ok(mut archive) = zip::ZipArchive::new(wheel) {
        // wheel file
        let arch = parts
            .next()
            .expect("Failed to get wheel target architecture");
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(AuditWheelError::ZipError)?;
            let lib_name = file.name().to_string();
            if lib_name.ends_with(".py") {
                continue;
            }
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)
                .map_err(AuditWheelError::IOError)?;
            if let Ok(elf) = Elf::parse(&buffer) {
                if !check_symbols(&lib_name, &elf, &buffer, arch, manylinux)? {
                    compliant = false;
                }
            }
        }
    } else {
        // maybe a dylib
        let buffer = fs_err::read(&opt.path).map_err(AuditWheelError::IOError)?;
        if let Ok(elf) = Elf::parse(&buffer) {
            let lib_name = opt
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .expect("Failed to get filename");
            let arch = match elf.header.e_machine {
                EM_X86_64 => "x86_64",
                EM_386 => "i686",
                EM_AARCH64 => "aarch64",
                EM_ARM => "armv7l",
                EM_S390 => "s390x",
                EM_PPC64 => {
                    if elf.little_endian {
                        "ppc64le"
                    } else {
                        "ppc64"
                    }
                }
                _ => {
                    eprintln!("Unsupported target architecture");
                    process::exit(1);
                }
            };
            if !check_symbols(&lib_name, &elf, &buffer, arch, manylinux)? {
                compliant = false;
            }
        }
    }
    if !compliant {
        process::exit(1);
    }
    Ok(())
}
