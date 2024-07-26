use curve25519_dalek::scalar::Scalar;

#[derive(Clone, Debug, PartialEq)]
pub struct SecretShare {
    pub index: u32,
    pub s: Scalar,
    pub t: Scalar,
}

const SECRET_SHARE_HRP: &str = "age-threshold-share-";

impl SecretShare {
    pub fn to_bech32(&self) -> String {
        let hrp = bech32::Hrp::parse(SECRET_SHARE_HRP).unwrap();
        let mut buf = [0u8; 68];
        buf[..4].copy_from_slice(&self.index.to_le_bytes());
        buf[4..36].copy_from_slice(&self.s.to_bytes());
        buf[36..].copy_from_slice(&self.t.to_bytes());
        bech32::encode::<bech32::Bech32>(hrp, &buf)
            .unwrap()
            .to_uppercase()
    }
    pub fn from_bech32(s: &str) -> Result<Self, &str> {
        let (hrp, data) = bech32::decode(s).or(Err("invalid bech32"))?;
        if hrp.as_str().to_lowercase() != SECRET_SHARE_HRP {
            return Err("invalid HRP");
        }
        let mut buf = [0u8; 68];
        if data.len() != 68 {
            return Err("invalid data length");
        }
        buf.copy_from_slice(&data[..]);
        Ok(SecretShare {
            index: u32::from_le_bytes(buf[..4].try_into().unwrap()),
            s: Scalar::from_bytes_mod_order(buf[4..36].try_into().unwrap()),
            t: Scalar::from_bytes_mod_order(buf[36..].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use hex_literal::hex;

    use super::SecretShare;

    #[test]
    fn test_example_to_bech32() {
        let example = SecretShare {
            index: 2,
            s: Scalar::from_bytes_mod_order(hex!(
                "07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a"
            )),
            t: Scalar::from_bytes_mod_order(hex!(
                "029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca476723"
            )),
        };
        let expected = "AGE-THRESHOLD-SHARE-1QGQQQQYVZEMA8ZL0C9LSQ3DSC544QPT7PLX8N5VJK0M3CKCUJ4J9YZVEPG502Q5VF3SJ5CSM3HCU3JW0D7F9H64AK5EJ02YKQZUVKNX2GANSXS4DHED";
        assert_eq!(example.to_bech32(), expected);
    }

    #[test]
    fn test_example_from_bech32() {
        let example = "AGE-THRESHOLD-SHARE-1QGQQQQYVZEMA8ZL0C9LSQ3DSC544QPT7PLX8N5VJK0M3CKCUJ4J9YZVEPG502Q5VF3SJ5CSM3HCU3JW0D7F9H64AK5EJ02YKQZUVKNX2GANSXS4DHED";
        let expected = SecretShare {
            index: 2,
            s: Scalar::from_bytes_mod_order(hex!(
                "07e22f5e44a542e8dc8e753a42251e1010cc79d192b3f71c5b1c95645209997a"
            )),
            t: Scalar::from_bytes_mod_order(hex!(
                "029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca476723"
            )),
        };
        assert_eq!(SecretShare::from_bech32(example), Ok(expected));
    }
}
