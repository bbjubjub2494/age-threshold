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
    #[test]
    fn test_example_plugin_large() {
        let example = "age1simplepq1qypqqq0mcqz9a5h8gx9hs6lgv57hwtwxmmxykvag4jq2wpkn3vpdakwzjdklxwdy9nqz25y7877fsz860mn63f20qyp9fggha0csmzd3rrugkvtzdv9x5ueh2nehndt484cvqzuxc6n3kxm335v80lf2pffncmk4jc2sufjnktcjjewhen5tq5pm2fzcuc6wespvnxt5h602vwz08d8dwdt8gjr36622esha9darmdp7c33gu27930zzk4ef0rr962k6n93f8y494re856y5d2f9nvlydfp7jjkqukry5hxvrya0y7z5tuz8eqvr09ungedyp0cd4rpk34rw89zjelumsev4fdg0c9e7dz2um0uz9dk42rqmjdstsjmghhqfxrrhu2kvyzzd9zcf59lyxhqqhe2vgxtk4tu6nztp5u6585twp6yfd8ae0x7gejh8vvevtx2e6y5yqqpcd6ruj8cd5dushvjp3ppn5zcj2v2ywh73sp7nxvjp6nf3yqqerhl0kxjleyjqs9n3wggcwety04lxpnsflqd36fmjlzg3658ytgn2z7zmsse5gf34hyr6ye2h462p5fjw9x0nsaule3nhgh32nq6pg5udgex4aej65fs9em7pckyy8rrj5fgl3v99r7uul93gth98z8je92lj9spsyeqc7vct9d5k2u9ycds69gsjah5m2s83zrq7extwlsvghcas9dpjmchm5gfazq3lmw7mrpy3gqyqw0dk2nfkqc4qg7phn3pu3njmt77gf97e9tvpksyhdjq92epmfenjpj0qg8q94df36fy6g53ugxeeg2ccdxlujm8p70zcq09kps96cd0mselpva4yyw3pqwjm6x5vhkf6ylklwkq2mvf5pac3avhvjnzw4rj6axgkj62gg2cuqrc2kwga839cmg9ceadwcx366r96emwzysnmq77nfwqzr7st8em9xcxcj7speyfjs9cm24wzzxx3pvyznwgfycrmwvtycvqyelh9sthcvnelexyey7fm9rxpgmsxym3m4wjuqajh6em3spemlcnsfw4s2whmqz9ytdzflrz24a5jthe33fh0vauhgqvkqwyqvmgxphr8yqe0rd9hrapmadaq3u4yfecxsz7tu6c8jecyc5nzs5usgd3v52mjc7sjvd38a5j4k8f3sytmndcyvxlac9g4lxw27vx9y9gptv64k6p93ga97q548kuxt6snwuh0ucmrsmyu8dj4gg0qqcknpzeld0yqygphq2zvmm8t2c6q4zeg83d0wdcha4yrtecgs5l7s6r3389sesvhapz2a27k03lanf38vcngrp536fkvu3pcwu204gqyyg2jm5mtyl2533ek2uv9j55wv7l4h4aghs5sw3c9g53wv5ur8wjunkx2dydv7ntnvzft2sgq7xg7jp3ykgggjzvjkq93nnwusqzyhc5e8q9mnnjvtkq0zhnss7a4kq3vvrc6f8w48qk2ns28umrwpv6lrggkpjzu48d42f5tk296ej379gwppxmef3qewyglhfgmffygw2z8jwxxz03hq83z6vrq65fjz6qspdyr5xvkn3d3c34hj8z2wgxpkrnhdwu48ym2c7n9emzkj97zfkanzd6wy5f60quw0uy83rz8sv86dfcc00aefywg4savg96jwk0yyfuy5fjy72srsy630ast4z0fqerehny2sprmzsdlpzm4cey5fh0hc87rng4mtw5y8lexltw50f73j0m3dy8rf7ex5eqnwt7hqfqlw9xc7u475es3h56f064ezddpqnttzxm65qazv2tk6qks4qr902z7u590heytktvtqme63q4qc9x4rx56hse5ru4zhxe9z6pqc046mfexz7sej8yv2h38hkurkgrl9f8d2j2dgc03707flw6k3a3gpgvr60yypeyp7tfkfv5hszrnd9khqmr9wpcsh8wpxw";
        let expected = AgeRecipient {
            plugin: Some("yubikey".to_string()),
            data: hex!("029dee4581274f12c8c6e00e87c32dbc5beabdb53327a89600b8cb4cca47672372")
                .to_vec(),
        };
        assert_eq!(AgeRecipient::from_bech32(example), Ok(expected));
        assert_eq!(expected.to_bech32(), example);
    }
}
