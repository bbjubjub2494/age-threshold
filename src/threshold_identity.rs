use bech32::{self, FromBase32, ToBase32, Variant};
use rlp::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct ThresholdIdentity {
    // empty placeholder
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
    use super::ThresholdIdentity;
    use hex_literal::hex;

    #[test]
    fn test_example() {
        let example = "AGE-PLUGIN-THRESHOLD-1CQLA364J";
        let expected = ThresholdIdentity {};
        assert_eq!(expected.encode(), example);
        assert_eq!(ThresholdIdentity::decode(example), Ok(expected));
    }
}
