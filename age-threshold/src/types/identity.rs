use std::str::FromStr;

/// Represents any Age identity, whether native or plugin.
pub enum AgeIdentity {
    X25519(age::x25519::Identity),
    Plugin(age::plugin::Identity),
}

impl AgeIdentity {
    pub fn from_bech32(s: &str) -> Result<Self, &str> {
        // FIXME: plugin support
        Ok(Self::X25519(age::x25519::Identity::from_str(s)?))
    }

    pub fn to_identity<C: age::Callbacks>(
        &self,
        callbacks: C,
    ) -> Result<Box<dyn age::Identity>, String> {
        match self {
            Self::X25519(i) => Ok(Box::new(i.clone())),
            Self::Plugin(i) => {
                let plugin_name = i.plugin();
                match age::plugin::IdentityPluginV1::new(
                    // FIXME: use one instance per plugin
                    plugin_name,
                    &[i.clone()],
                    callbacks,
                ) {
                    Err(age::DecryptError::MissingPlugin { binary_name }) => Err(format!(
                        "No plugin found for {}: {}",
                        plugin_name, binary_name
                    )),
                    Ok(plugin) => Ok(Box::new(plugin)),
                    _ => panic!("unexpected error"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AgeIdentity;
    use age_core::secrecy::ExposeSecret;

    #[test]
    fn test_example_no_plugin() {
        let example = "AGE-SECRET-KEY-1QL3Z7HJY54PW3HYWW5AYYFG7ZQGVC7W3J2ELW8ZMRJ2KG5SFN9AQGHWZHJ";
        assert!(
            matches!(AgeIdentity::from_bech32(example), Ok(AgeIdentity::X25519(actual)) if actual.to_string().expose_secret() == example)
        );
    }
}
