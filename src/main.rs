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
use regex::Regex;
use structopt::StructOpt;
use thiserror::Error;

mod policy;

/// Error raised during auditing an elf file for manylinux compatibility
#[derive(Error, Debug)]
#[error("Ensuring manylinux compliance failed")]
enum AuditWheelError {
    /// The wheel couldn't be read
    #[error("Failed to read the wheel")]
    IoError(#[source] io::Error),
    /// The wheel couldn't be read
    #[error("Failed to read the wheel")]
    ZipError(#[source] zip::result::ZipError),
}

#[derive(Clone, Debug)]
struct VersionedLibrary {
    /// library name
    name: String,
    /// versions needed
    versions: HashSet<String>,
}

/// Find required dynamic linked libraries with version information
fn find_versioned_libraries(elf: &Elf) -> Result<Vec<VersionedLibrary>, AuditWheelError> {
    let mut symbols = Vec::new();
    if let Some(verneed) = &elf.verneed {
        for need_file in verneed.iter() {
            if let Some(name) = elf.dynstrtab.get_at(need_file.vn_file) {
                // Skip dynamic linker/loader
                if name.starts_with("ld-linux") || name == "ld64.so.2" || name == "ld64.so.1" {
                    continue;
                }
                let mut versions = HashSet::new();
                for need_ver in need_file.iter() {
                    if let Some(aux_name) = elf.dynstrtab.get_at(need_ver.vna_name) {
                        versions.insert(aux_name.to_string());
                    }
                }
                symbols.push(VersionedLibrary {
                    name: name.to_string(),
                    versions,
                });
            }
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
            let name = strtab.get_at(sym.st_name).unwrap_or("BAD NAME");
            for symbol_version in symbol_versions {
                if name.ends_with(&format!("@{}", symbol_version)) {
                    symbols.push(name.to_string());
                }
            }
        }
    }
    Ok(symbols)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct Manylinux {
    x: u16,
    y: u16,
}

impl Manylinux {
    fn new(x: u16, y: u16) -> Self {
        Self { x, y }
    }
}

impl fmt::Display for Manylinux {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "manylinux_{}_{}", self.x, self.y)
    }
}

impl FromStr for Manylinux {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "2_5" | "1" | "manylinux1" => Ok(Manylinux::new(2, 5)),
            "2_12" | "2010" | "manylinux2010" => Ok(Manylinux::new(2, 12)),
            "2_17" | "2014" | "manylinux2014" => Ok(Manylinux::new(2, 17)),
            _ => {
                let value = value.strip_prefix("manylinux_").unwrap_or(value);
                let mut parts = value.split('_');
                let x = parts
                    .next()
                    .and_then(|x| x.parse::<u16>().ok())
                    .ok_or("invalid manylinux option")?;
                let y = parts
                    .next()
                    .and_then(|y| y.parse::<u16>().ok())
                    .ok_or("invalid manylinux option")?;
                Ok(Manylinux::new(x, y))
            }
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "auditwheel-symbols")]
struct Opt {
    #[structopt(
        short,
        long,
        possible_values = &["1", "2010", "2014", "2_5", "2_12", "2_17", "2_24", "2_27", "2_28", "2_31", "2_34", "2_35"],
        case_insensitive = true,
    )]
    manylinux: Option<Manylinux>,
    #[structopt(name = "FILE", parse(from_os_str))]
    path: PathBuf,
}

fn check_symbols(lib_name: &str, elf: &Elf, manylinux: Manylinux) -> Result<bool, AuditWheelError> {
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

    let policies = crate::policy::Policy::load();
    let policy = policies
        .iter()
        .find(|p| p.name == manylinux.to_string())
        .unwrap();
    if !policy.symbol_versions.contains_key(arch) {
        eprintln!(
            "{} is not {} compliant because it has unsupported architecture {}",
            lib_name,
            policy.description(),
            arch
        );
        return Ok(false);
    }
    // This returns essentially the same as ldd
    let deps: Vec<String> = elf.libraries.iter().map(ToString::to_string).collect();
    let versioned_libraries = find_versioned_libraries(&elf)?;

    let mut offending_libs = HashSet::new();
    let mut offending_blacklist_syms = HashMap::new();
    let undef_symbols: HashSet<String> = elf
        .dynsyms
        .iter()
        .filter_map(|sym| {
            if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
                elf.dynstrtab.get_at(sym.st_name).map(ToString::to_string)
            } else {
                None
            }
        })
        .collect();
    for dep in deps {
        // Skip dynamic linker/loader
        if dep.starts_with("ld-linux") || dep == "ld64.so.2" || dep == "ld64.so.1" {
            continue;
        }
        if !policy.lib_whitelist.contains(&dep) {
            offending_libs.insert(dep.clone());
        }
        if let Some(sym_list) = policy.blacklist.get(&dep) {
            let mut intersection: Vec<_> = sym_list.intersection(&undef_symbols).cloned().collect();
            if !intersection.is_empty() {
                intersection.sort();
                offending_blacklist_syms.insert(dep, intersection);
            }
        }
    }
    for library in versioned_libraries {
        if !policy.lib_whitelist.contains(&library.name) {
            offending_libs.insert(library.name.clone());
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
                        "{}\toffending versions: {}",
                        library.name,
                        offending_symbol_versions.join(", ")
                    )
                } else {
                    format!(
                        "{}\toffending symbols: {}",
                        library.name,
                        offending_symbols.join(", ")
                    )
                };
                offending_libs.insert(offender);
            }
        }
    }

    // Checks if we can give a more helpful error message
    let is_libpython = Regex::new(r"^libpython3\.\d+\.so\.\d+\.\d+$").unwrap();
    let mut offenders: Vec<String> = offending_libs.into_iter().collect();
    for (lib, syms) in offending_blacklist_syms {
        offenders.push(format!(
            "{} offending black-listed symbols: {}",
            lib,
            syms.join(", ")
        ));
    }
    match offenders.as_slice() {
        [] => eprintln!("{} is {} compliant.", lib_name, policy.description()),
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
                lib_name,
                policy.description()
            );
            for offender in offenders {
                eprintln!("{}", offender);
            }
            return Ok(false);
        }
    }
    Ok(true)
}

fn parse_platform_from_filename(filename: &str) -> Vec<Manylinux> {
    let wheel_type = filename
        .rsplitn(2, '-')
        .next()
        .expect("Failed to get wheel type");
    let mut platforms = Vec::new();
    let mut found = HashSet::new();
    for tag in wheel_type.split('.') {
        if tag.starts_with("linux") {
            continue;
        }
        let tag = tag.strip_prefix("manylinux").unwrap_or(tag);
        let manylinux = if tag.starts_with("_") {
            // manylinux_x_y_arch
            let parts: Vec<&str> = tag[1..].split('_').collect();
            let manylinux = parts[..2].join("_");
            manylinux
        } else {
            // manylinuxYEAR_arch
            if let Some((ver, _arch)) = tag.split_once('_') {
                ver.to_string()
            } else {
                continue;
            }
        };
        if let Ok(manylinux) = manylinux.parse::<Manylinux>() {
            if !found.contains(&manylinux) {
                found.insert(manylinux);
                platforms.push(manylinux);
            }
        }
    }
    platforms
}

fn main() -> Result<(), AuditWheelError> {
    let opt = Opt::from_args();
    let filename = opt
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("Failed to get wheel filename");
    let mut platforms = parse_platform_from_filename(filename);
    if platforms.is_empty() && opt.manylinux.is_some() {
        platforms.push(opt.manylinux.unwrap());
    }
    let mut compliant = true;
    for tag in platforms {
        let manylinux = opt.manylinux.unwrap_or(tag);
        let wheel = fs_err::File::open(&opt.path).map_err(AuditWheelError::IoError)?;
        if let Ok(mut archive) = zip::ZipArchive::new(wheel) {
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(AuditWheelError::ZipError)?;
                let lib_name = file.name().to_string();
                if lib_name.ends_with(".py") {
                    continue;
                }
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)
                    .map_err(AuditWheelError::IoError)?;
                if let Ok(elf) = Elf::parse(&buffer) {
                    if !check_symbols(&lib_name, &elf, manylinux)? {
                        compliant = false;
                    }
                }
            }
        } else {
            // maybe a dylib
            let buffer = fs_err::read(&opt.path).map_err(AuditWheelError::IoError)?;
            if let Ok(elf) = Elf::parse(&buffer) {
                let lib_name = opt
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .expect("Failed to get filename");
                if !check_symbols(&lib_name, &elf, manylinux)? {
                    compliant = false;
                }
            }
        }
    }
    if !compliant {
        process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_platform_from_filename, Manylinux};

    #[test]
    fn test_parse_platform() {
        assert_eq!(
            parse_platform_from_filename(
                "auditwheel_symbols-0.1.7-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64"
            ),
            vec![(Manylinux::new(2, 12), "x86_64".to_string()),],
        );
        assert_eq!(
            parse_platform_from_filename(
                "auditwheel_symbols-0.1.7-py3-none-manylinux_2_12_i686.manylinux2010_i686"
            ),
            vec![(Manylinux::new(2, 12), "i686".to_string()),],
        );
        assert_eq!(
            parse_platform_from_filename("auditwheel_symbols-0.1.7-py3-none-manylinux2010_x86_64"),
            vec![(Manylinux::new(2, 12), "x86_64".to_string())],
        );
        assert_eq!(
            parse_platform_from_filename("auditwheel_symbols-0.1.7-py3-none-manylinux_2_12_x86_64"),
            vec![(Manylinux::new(2, 12), "x86_64".to_string())],
        );
    }
}
