//! MAC vendor names from the IEEE registry export: https://standards-oui.ieee.org/oui/oui.csv

use std::collections::HashMap;

pub struct Vendors {
    by_prefix: HashMap<String, String>,
}

impl Vendors {
    pub fn load(path: &str) -> Option<Self> {
        Some(Self::parse(&std::fs::read_to_string(path).ok()?))
    }

    /// Rows look like `MA-L,286FB9,"Acme, Inc.",Some Address`.
    pub fn parse(csv: &str) -> Self {
        let by_prefix = csv
            .lines()
            .filter_map(|line| {
                let mut fields = line.splitn(3, ',');
                let (_registry, prefix, rest) = (fields.next()?, fields.next()?, fields.next()?);
                let name = match rest.strip_prefix('"') {
                    Some(quoted) => quoted.split('"').next()?,
                    None => rest.split(',').next()?,
                };
                Some((prefix.to_uppercase(), name.trim().to_string()))
            })
            .collect();
        Self { by_prefix }
    }

    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let digits: String = mac.chars().filter(char::is_ascii_hexdigit).collect();
        self.by_prefix.get(&digits.get(..6)?.to_uppercase()).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Registry,Assignment,Organization Name,Organization Address\n\
MA-L,286FB9,\"Acme, Inc.\",\"1 Road, Town\"\n\
MA-L,08EA1F,Plain Vendor,Street 2\n";

    #[test]
    fn finds_quoted_and_plain_vendors_in_any_mac_format() {
        let vendors = Vendors::parse(SAMPLE);
        assert_eq!(vendors.lookup("28:6f:b9:00:11:22"), Some("Acme, Inc."));
        assert_eq!(vendors.lookup("08-EA-1F-00-11-22"), Some("Plain Vendor"));
        assert_eq!(vendors.lookup("00:00:00:00:00:00"), None);
    }

    #[test]
    fn short_input_is_not_an_error() {
        assert_eq!(Vendors::parse(SAMPLE).lookup("28:6f"), None);
    }
}
