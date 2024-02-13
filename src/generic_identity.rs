use bech32::{self, FromBase32, ToBase32, Variant};
use rlp::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct GenericIdentity {
    pub plugin: Option<String>,
    pub data: Vec<u8>,
}

const NATIVE_IDENTITY_HRP: &str = "age-secret-key-";
const PLUGIN_IDENTITY_HRP_PREFIX: &str = "age-plugin-";

impl GenericIdentity {
    pub fn encode(self: &Self) -> String {
        let hrp = match self.plugin {
            None => NATIVE_IDENTITY_HRP.to_string(),
            Some(ref plugin) => PLUGIN_IDENTITY_HRP_PREFIX.to_string() + plugin,
        };
        bech32::encode(
            &hrp,
            &self.data.to_base32(),
            Variant::Bech32,
        )
        .unwrap()
        .to_uppercase()
    }
    pub fn decode(s: &str) -> Result<Self, &str> {
        let (hrp, b32data, _) = bech32::decode(s).or(Err("invalid bech32"))?;
        let plugin = if hrp == NATIVE_IDENTITY_HRP {
            None
        } else if hrp.starts_with(PLUGIN_IDENTITY_HRP_PREFIX) {
            Some(hrp[PLUGIN_IDENTITY_HRP_PREFIX.len()..].to_string())
        } else {
            Err("invalid HRP")?
        };
        let data = Vec::<u8>::from_base32(b32data.as_slice()).or(Err("invalid base32"))?;
        Ok(GenericIdentity { plugin, data })
    }

    /*
    pub fn to_identity<C: age::Callbacks>(
        self: &Self,
        callbacks: C,
    ) -> Result<Box<dyn age::Identity>, String> {
        match self.plugin {
            None => Ok(Box::new(
                age::x25519::Identity::from_str(&self.encode()).unwrap(),
            )),
            // TODO: ssh
            Some(ref plugin_name) => match age::plugin::IdentityPluginV1::new(
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
    */
}
