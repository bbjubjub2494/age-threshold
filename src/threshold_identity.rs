use bech32::{self, FromBase32, ToBase32, Variant};
use rlp::{RlpDecodable, RlpEncodable};
use crate::generic_identity::GenericIdentity;

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct ThresholdIdentity {
    pub inner_identity: GenericIdentity
}

const PLUGIN_IDENTITY_HRP: &str = "age-plugin-threshold-";

// FIXME: probably don't need RLP?
impl ThresholdIdentity {
    pub fn encode(self: &Self) -> String {
        bech32::encode(
            PLUGIN_IDENTITY_HRP,
            rlp::encode(self).to_base32(),
            Variant::Bech32,
        )
        .unwrap()
        .to_uppercase()
    }
    pub fn decode(s: &str) -> Result<Self, &str> {
        let (hrp, b32data, _) = bech32::decode(s).or(Err("invalid bech32"))?;
        if hrp != PLUGIN_IDENTITY_HRP {
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
    use super::{GenericIdentity, ThresholdIdentity};
    use hex_literal::hex;

    #[test]
    fn test_example() {
        let example = "AGE-PLUGIN-THRESHOLD-1ALHVPMQ8S83Z7HJYSXJ59Q0GS8WGRRN48FPZ28SSZZQUC7VP6XQE9QDNS8M3CKCUSX2KG5SFSXVH5L25PMT";
        let expected = ThresholdIdentity { inner_identity: GenericIdentity {
            plugin: None,
            data: hex!("07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a").to_vec(),
        }};
        assert_eq!(expected.encode(), example);
        assert_eq!(ThresholdIdentity::decode(example), Ok(expected));
    }
}
