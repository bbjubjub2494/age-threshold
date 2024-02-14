use bech32::{self, FromBase32, ToBase32, Variant};
use rlp::{RlpDecodable, RlpEncodable};
use crate::types::GenericIdentity;

/// Wrap an arbitrary Age identity so it can be passed to the threshold plugin.
///
/// Inner identities do not need to have any special properties. All this wrapper does is change
/// the human-readable part of the bech32 encoding to `AGE-PLUGIN-THRESHOLD-`. This ensures that
/// Age invokes the plugin and passes the identity to it.
#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct ThresholdIdentity {
    pub inner_identity: GenericIdentity
}

const PLUGIN_IDENTITY_HRP: &str = "age-plugin-threshold-";

impl ThresholdIdentity {
    pub fn to_bech32(self: &Self) -> String {
        bech32::encode(
            PLUGIN_IDENTITY_HRP,
            rlp::encode(self).to_base32(),
            Variant::Bech32,
        )
        .unwrap()
        .to_uppercase()
    }
    pub fn from_bech32(s: &str) -> Result<Self, &str> {
        let (hrp, b32data, _) = bech32::decode(s).or(Err("invalid bech32"))?;
        if hrp != PLUGIN_IDENTITY_HRP {
            Err("invalid HRP")?
        }
        let data = Vec::<u8>::from_base32(b32data.as_slice()).or(Err("invalid base32"))?;
        rlp::decode(data.as_slice()).or(Err("RLP decoding error"))
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
        assert_eq!(expected.to_bech32(), example);
        assert_eq!(ThresholdIdentity::from_bech32(example), Ok(expected));
    }
}
