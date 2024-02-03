use crate::generic_recipient::GenericRecipient;
use bech32::{self, FromBase32, ToBase32, Variant};
use rlp::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct ThresholdRecipient {
    pub t: u16,
    pub recipients: Vec<GenericRecipient>,
}

const PLUGIN_RECIPIENT_HRP: &str = "age1threshold";

impl ThresholdRecipient {
    pub fn encode(self: &Self) -> String {
        bech32::encode(
            PLUGIN_RECIPIENT_HRP,
            rlp::encode(self).to_base32(),
            Variant::Bech32,
        )
        .unwrap()
    }
    pub fn decode(s: &str) -> Result<Self, &str> {
        let (hrp, b32data, _) = bech32::decode(s).or(Err("invalid bech32"))?;
        dbg!(&hrp);
        if hrp != PLUGIN_RECIPIENT_HRP {
            Err("invalid HRP")?
        }
        let data = Vec::<u8>::from_base32(b32data.as_slice()).or(Err("invalid base32"))?;
        rlp::decode(data.as_slice()).or(Err("RLP decoding error"))
    }
    pub fn from_rlp(data: &[u8]) -> Result<Self, &str> {
        rlp::decode(data).or(Err("RLP decoding error"))
    }
}

#[cfg(test)]
mod tests {
    use super::{GenericRecipient, ThresholdRecipient};
    use hex_literal::hex;

    #[test]
    fn test_example() {
        let example = "age1threshold1lpcqr7rdamqwcpupugh4u3yp54pgr6ypmjqcuaf6ggj3uyqss8x8nqw3sxfgrvup7uw9k8ypj4j9yzvpn9a0s0xgsauh2cnfddjhnuszsxwcrmj9sxqjwncjs8ygr35puq8grpupcvkcr0zms84gr0vpk5ej0qdgsxtgpqdcs895eqw2ganjxus8cuy3y";
        let expected = ThresholdRecipient {
            t: 1,
            recipients: vec![
                GenericRecipient {
                    plugin: None,
                    data: hex!("07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a")
                        .to_vec(),
                },
                GenericRecipient {
                    plugin: Some("yubikey".to_string()),
                    data: hex!(
                        "029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca47672372"
                    )
                    .to_vec(),
                },
            ],
        };
        assert_eq!(expected.encode(), example);
        assert_eq!(ThresholdRecipient::decode(example), Ok(expected));
    }
}
