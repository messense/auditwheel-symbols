use std::collections::{HashMap, HashSet};

use serde::Deserialize;

/// Manylinux policy
#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct Policy {
    /// manylinux platform tag name
    pub name: String,
    /// manylinux platform tag aliases
    pub aliases: Vec<String>,
    /// policy priority
    pub priority: i64,
    /// platform architecture to symbol versions map
    #[serde(rename = "symbol_versions")]
    pub symbol_versions: HashMap<String, HashMap<String, HashSet<String>>>,
    /// whitelisted libraries
    #[serde(rename = "lib_whitelist")]
    pub lib_whitelist: HashSet<String>,
    /// blacklisted symbols of whitelisted libraries
    pub blacklist: HashMap<String, HashSet<String>>,
}

impl Policy {
    pub fn load() -> Vec<Self> {
        serde_json::from_slice(include_bytes!("policy.json")).expect("invalid policy.json")
    }

    pub fn description(&self) -> String {
        if self.aliases.is_empty() {
            self.name.clone()
        } else {
            format!("{}(aka {})", &self.name, self.aliases.join(","))
        }
    }
}

#[cfg(test)]
mod test {
    use super::Policy;

    #[test]
    fn test_load_policy() {
        let policies = Policy::load();
        let linux = policies.iter().find(|p| p.name == "linux").unwrap();
        assert!(linux.symbol_versions.is_empty());
        assert!(linux.lib_whitelist.is_empty());

        let manylinux2010 = policies
            .iter()
            .find(|p| p.name == "manylinux2010" || p.aliases.contains(&"manylinux2010".to_string()))
            .unwrap();
        assert!(manylinux2010.lib_whitelist.contains("libc.so.6"));
        let symbol_version = &manylinux2010.symbol_versions["x86_64"];
        assert_eq!(symbol_version["CXXABI"].len(), 4);
        let cxxabi = &symbol_version["CXXABI"];
        for version in &["1.3", "1.3.1", "1.3.2", "1.3.3"] {
            assert!(cxxabi.contains(*version));
        }
    }
}
