use bech32::{FromBase32, ToBase32, Variant};
use rlp::{RlpDecodable, RlpEncodable};
use std::str::FromStr;

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct GenericRecipient {
    pub plugin: Option<String>,
    pub data: Vec<u8>,
}

const PLUGIN_RECIPIENT_PREFIX: &str = "age1";

impl GenericRecipient {
    // needed for conversions
    fn encode(self: &Self) -> String {
        let hrp = match self.plugin {
            None => "age".to_string(),
            Some(ref plugin) => "age1".to_string() + plugin,
        };
        bech32::encode(&hrp, self.data.to_base32(), Variant::Bech32).unwrap()
    }
    fn decode(s: &str) -> Result<Self, &str> {
        let (hrp, data, _) = bech32::decode(s).or(Err("invalid bech32"))?;
        dbg!(&hrp);
        let plugin = if hrp == "age" {
            None
        } else if hrp.starts_with(PLUGIN_RECIPIENT_PREFIX) {
            Some(hrp.split_at(PLUGIN_RECIPIENT_PREFIX.len()).1.to_owned())
        } else {
            Err("invalid HRP")?
        };
        Ok(GenericRecipient {
            plugin: plugin,
            data: Vec::<u8>::from_base32(data.as_slice())
                .or(Err("base32 decoding"))?
                .to_owned(),
        })
    }

    pub fn to_recipient<C: age::Callbacks>(
        self: &Self,
        callbacks: C,
    ) -> Result<Box<dyn age::Recipient>, String> {
        match self.plugin {
            None => Ok(Box::new(
                age::x25519::Recipient::from_str(&self.encode()).unwrap(),
            )),
            // TODO: ssh
            Some(ref plugin_name) => match age::plugin::RecipientPluginV1::new(
                plugin_name,
                &[age::plugin::Recipient::from_str(&self.encode()).unwrap()],
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
    use super::GenericRecipient;
    use hex_literal::hex;

    #[test]
    fn test_example_no_plugin() {
        let example = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let expected = GenericRecipient {
                plugin: None,
                data: hex!("07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a")
                    .to_vec()
            };
        assert_eq!(
            GenericRecipient::decode(example),
            Ok(expected)
        );
        assert_eq!(expected.encode(), example);
    }
    #[test]
    fn test_example_plugin() {
        let example = "age1yubikey1q2w7u3vpya839jxxuq8g0sedh3d740d4xvn639sqhr95ejj8vu3hyfumptt";
        let expected = GenericRecipient {
                plugin: Some("yubikey".to_string()),
                data: hex!("029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca47672372")
                    .to_vec()
            };
        assert_eq!(
            GenericRecipient::decode(example),
            Ok(expected)
        );
        assert_eq!(expected.encode(), example);
    }
}
