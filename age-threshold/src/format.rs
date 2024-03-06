use age_core::format::Stanza;
use curve25519_dalek::ristretto::RistrettoPoint;

const VERSION_LINE: &[u8] = b"bbjubjub.fr/age-threshold/v0\n";

#[derive(Debug)]
pub struct Header {
    pub threshold: usize,
    pub commitments: Vec<RistrettoPoint>,
    pub enc_shares: Vec<EncShare>,
}

#[derive(Debug)]
pub struct EncShare {
    pub index: u32,
    pub ciphertext: Vec<u8>,
    pub stanzas: Vec<Stanza>,
}

pub mod read {
    use nom::bytes::streaming::tag;
    use nom::error::{Error, ErrorKind};
    use nom::multi::many_till;
    use nom::IResult;

    use age_core::format::read::age_stanza;

    use base64::{engine::general_purpose::STANDARD, Engine as _};

    use curve25519_dalek::ristretto::CompressedRistretto;

    use super::{EncShare, Header, VERSION_LINE};

    fn version_line(input: &[u8]) -> IResult<&[u8], ()> {
        let (input, _) = tag(VERSION_LINE)(input)?;
        Ok((input, ()))
    }

    fn hmac_line(input: &[u8]) -> IResult<&[u8], ()> {
        // TODO: do the HMAC
        let (input, _) = tag(b"---\n")(input)?;
        Ok((input, ()))
    }

    pub fn header<'a>(input: &[u8]) -> IResult<&[u8], Header> {
        let (input, ()) = version_line(input)?;
        let (input, stanza) = age_stanza(input)?;
        if stanza.tag != "threshold" {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag)));
        }
        let threshold = stanza.args[0]
            .parse()
            .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?;
        let (input, stanza) = age_stanza(input)?;
        if stanza.tag != "commitments" {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Tag)));
        }
        let mut commitments = vec![];
        for arg in stanza.args {
            let c = CompressedRistretto::from_slice(
                STANDARD
                    .decode(arg)
                    .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?
                    .as_slice(),
            )
            .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?
            .decompress()
            .ok_or(nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?;
            commitments.push(c);
        }
        let (input, (mut stanzas, _)) = many_till(age_stanza, hmac_line)(input)?;
        let mut current_share = None;
        let mut enc_shares = vec![];
        for s in stanzas.drain(..) {
            if s.tag == "share" {
                if let Some(share) = current_share {
                    enc_shares.push(share);
                }
                current_share = Some(EncShare {
                    index: s.args[0]
                        .parse()
                        .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?,
                    ciphertext: s.body().into(),
                    stanzas: vec![],
                });
            } else {
                let mut v =
                    current_share.ok_or(nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?;
                v.stanzas.push(s.into());
                current_share = Some(v);
            }
        }
        enc_shares
            .push(current_share.ok_or(nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?);
        Ok((
            input,
            Header {
                threshold,
                commitments,
                enc_shares,
            },
        ))
    }
}

pub mod write {
    use cookie_factory::combinator::slice;
    use cookie_factory::{GenResult, WriteContext};

    use base64::{engine::general_purpose::STANDARD, Engine as _};

    use age_core::format::write::age_stanza;

    use std::io::Write;

    use super::{EncShare, RistrettoPoint, VERSION_LINE};

    fn version_line<W: Write>(wc: WriteContext<W>) -> GenResult<W> {
        slice(VERSION_LINE)(wc)
    }

    fn hmac_line<W: Write>(wc: WriteContext<W>) -> GenResult<W> {
        // TODO: do the HMAC
        slice("---\n")(wc)
    }

    pub fn header<'a, W: Write>(
        t: usize,
        commitments: &'a Vec<RistrettoPoint>,
        enc_shares: &'a Vec<EncShare>,
    ) -> impl Fn(WriteContext<W>) -> GenResult<W> + 'a {
        move |mut wc| {
            wc = version_line(wc)?;
            wc = age_stanza("threshold", &[&t.to_string()], &[])(wc)?;
            let args: Vec<_> = commitments
                .iter()
                .map(|c| STANDARD.encode(c.compress().as_bytes()))
                .collect();
            wc = age_stanza("commitments", &args[..], &[])(wc)?;
            for es in enc_shares {
                wc = age_stanza("share", &[es.index.to_string()], &es.ciphertext)(wc)?;
                for s in &es.stanzas {
                    wc = age_stanza(&s.tag, &s.args, &s.body)(wc)?;
                }
            }
            wc = hmac_line(wc)?;
            Ok(wc)
        }
    }
}
