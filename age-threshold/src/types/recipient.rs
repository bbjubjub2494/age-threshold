use std::str::FromStr;

/// Represents any Age recipient, whether native or plugin.
#[derive(Debug, PartialEq, Clone)]
pub struct AgeRecipient {
    pub plugin: Option<String>,
    pub data: Vec<u8>,
}

const NATIVE_RECIPIENT_HRP: &str = "age";
const PLUGIN_RECIPIENT_HRP_PREFIX: &str = "age1";

impl AgeRecipient {
    // needed for conversions
    pub fn to_bech32(&self) -> String {
        let hrp = match self.plugin {
            None => bech32::Hrp::parse(NATIVE_RECIPIENT_HRP).unwrap(),
            Some(ref plugin) => {
                bech32::Hrp::parse(&(PLUGIN_RECIPIENT_HRP_PREFIX.to_owned() + plugin)).unwrap()
            }
        };
        bech32::encode::<bech32::Bech32>(hrp, &self.data).unwrap()
    }
    pub fn from_bech32(s: &str) -> Result<Self, &str> {
        let (hrp, data) = bech32::decode(s).or(Err("invalid bech32"))?;
        let plugin = if hrp.as_str() == NATIVE_RECIPIENT_HRP {
            None
        } else if hrp.as_str().starts_with(PLUGIN_RECIPIENT_HRP_PREFIX) {
            Some(
                hrp.as_str()
                    .split_at(PLUGIN_RECIPIENT_HRP_PREFIX.len())
                    .1
                    .to_owned(),
            )
        } else {
            Err("invalid HRP")?
        };
        Ok(AgeRecipient { plugin, data })
    }

    pub fn to_recipient<C: age::Callbacks>(
        &self,
        callbacks: C,
    ) -> Result<Box<dyn age::Recipient>, String> {
        match self.plugin {
            None => Ok(Box::new(
                age::x25519::Recipient::from_str(&self.to_bech32()).unwrap(),
            )),
            Some(ref plugin_name) => match age::plugin::RecipientPluginV1::new(
                plugin_name,
                &[age::plugin::Recipient::from_str(&self.to_bech32()).unwrap()],
                &[],
                callbacks,
            ) {
                Err(age::EncryptError::MissingPlugin { binary_name }) => Err(format!(
                    "No plugin found for {}: {}",
                    plugin_name, binary_name
                )),
                Ok(plugin) => Ok(Box::new(plugin)),
                _ => panic!("unexpected error"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AgeRecipient;
    use hex_literal::hex;

    #[test]
    fn test_example_no_plugin() {
        let example = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let expected = AgeRecipient {
            plugin: None,
            data: hex!("07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a").to_vec(),
        };
        assert_eq!(expected.to_bech32(), example);
        assert_eq!(AgeRecipient::from_bech32(example), Ok(expected));
    }
    #[test]
    fn test_example_plugin() {
        let example = "age1yubikey1q2w7u3vpya839jxxuq8g0sedh3d740d4xvn639sqhr95ejj8vu3hyfumptt";
        let expected = AgeRecipient {
            plugin: Some("yubikey".to_string()),
            data: hex!("029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca47672372")
                .to_vec(),
        };
        assert_eq!(expected.to_bech32(), example);
        assert_eq!(AgeRecipient::from_bech32(example), Ok(expected));
    }
}
