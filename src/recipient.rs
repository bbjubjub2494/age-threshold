use bech32::{self, FromBase32};
use rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Recipient {
    pub plugin: Option<String>,
    pub data: Vec<u8>,
}

const PLUGIN_RECIPIENT_PREFIX: &str = "age1";

impl Recipient {
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
        Ok(Recipient {
            plugin: plugin,
            data: Vec::<u8>::from_base32(data.as_slice())
                .or(Err("base32 decoding"))?
                .to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Recipient;
    use hex_literal::hex;

    #[test]
    fn test_example_no_plugin() {
        let example = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        assert_eq!(
            Recipient::decode(example),
            Ok(Recipient {
                plugin: None,
                data: hex!("07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a")
                    .to_vec()
            })
        );
    }
    #[test]
    fn test_example_plugin() {
        let example = "age1yubikey1q2w7u3vpya839jxxuq8g0sedh3d740d4xvn639sqhr95ejj8vu3hyfumptt";
        assert_eq!(
            Recipient::decode(example),
            Ok(Recipient {
                plugin: Some("yubikey".to_string()),
                data: hex!("029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca47672372")
                    .to_vec()
            })
        );
    }
}
