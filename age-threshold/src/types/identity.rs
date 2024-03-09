use std::str::FromStr;

/// Represents any Age identity, whether native or plugin.
#[derive(Clone, Debug, PartialEq)]
pub struct AgeIdentity {
    pub plugin: Option<String>,
    pub data: Vec<u8>,
}

const NATIVE_IDENTITY_HRP: &str = "age-secret-key-";
const PLUGIN_IDENTITY_HRP_PREFIX: &str = "age-plugin-";

impl AgeIdentity {
    pub fn to_bech32(self: &Self) -> String {
        let hrp = match self.plugin {
            None => bech32::Hrp::parse(NATIVE_IDENTITY_HRP).unwrap(),
            Some(ref plugin) => {
                bech32::Hrp::parse(&(PLUGIN_IDENTITY_HRP_PREFIX.to_owned() + plugin)).unwrap()
            }
        };
        bech32::encode::<bech32::Bech32>(hrp, &self.data)
            .unwrap()
            .to_uppercase()
    }
    pub fn from_bech32(s: &str) -> Result<Self, &str> {
        let (hrp, data) = bech32::decode(s).or(Err("invalid bech32"))?;
        let plugin = if hrp.as_str() == NATIVE_IDENTITY_HRP {
            None
        } else if hrp.as_str().starts_with(PLUGIN_IDENTITY_HRP_PREFIX) {
            Some(hrp.as_str()[PLUGIN_IDENTITY_HRP_PREFIX.len()..].to_owned())
        } else {
            Err("invalid HRP")?
        };
        Ok(AgeIdentity { plugin, data })
    }

    pub fn to_identity<C: age::Callbacks>(
        self: &Self,
        callbacks: C,
    ) -> Result<Box<dyn age::Identity>, String> {
        match self.plugin {
            None => Ok(Box::new(
                age::x25519::Identity::from_str(&self.to_bech32()).unwrap(),
            )),
            Some(ref plugin_name) => match age::plugin::IdentityPluginV1::new(
                plugin_name,
                &[age::plugin::Identity::from_str(&self.to_bech32()).unwrap()],
                callbacks,
            ) {
                Err(age::DecryptError::MissingPlugin { binary_name }) => Err(format!(
                    "No plugin found for {}: {}",
                    plugin_name, binary_name
                )),
                Ok(plugin) => Ok(Box::new(plugin)),
                _ => panic!("unexpected error"),
            },
        }
    }
}
