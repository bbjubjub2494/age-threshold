use nom::bytes::streaming::tag;
use nom::error::{Error, ErrorKind};
use nom::multi::many_till;
use nom::IResult;

use age_core::format::read::age_stanza;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use curve25519_dalek::ristretto::CompressedRistretto;

use crate::format::common::VERSION_LINE;
use crate::types::{EncShare, Header};

fn version_line(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag(VERSION_LINE)(input)?;
    Ok((input, ()))
}

fn hmac_line(input: &[u8]) -> IResult<&[u8], ()> {
    // TODO: do the HMAC
    let (input, _) = tag(b"---\n")(input)?;
    Ok((input, ()))
}

pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
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
                ciphertext: s.body(),
                stanzas: vec![],
            });
        } else {
            let mut v =
                current_share.ok_or(nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?;
            v.stanzas.push(s.into());
            current_share = Some(v);
        }
    }
    enc_shares.push(current_share.ok_or(nom::Err::Error(Error::new(input, ErrorKind::Satisfy)))?);
    Ok((
        input,
        Header {
            threshold,
            commitments,
            enc_shares,
        },
    ))
}
