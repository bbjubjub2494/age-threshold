use cookie_factory::combinator::slice;
use cookie_factory::{GenResult, WriteContext};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use age_core::format::write::age_stanza;

use std::io::Write;

use curve25519_dalek::RistrettoPoint;

use crate::format::common::VERSION_LINE;
use crate::types::EncShare;

fn base64encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn version_line<W: Write>(wc: WriteContext<W>) -> GenResult<W> {
    slice(VERSION_LINE)(wc)
}

fn hmac_line<W: Write>(wc: WriteContext<W>) -> GenResult<W> {
    // TODO: do the HMAC
    slice("---\n")(wc)
}

pub fn header<'a, W: Write>(
    t: usize,
    commitments: &'a [RistrettoPoint],
    enc_shares: &'a [EncShare],
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
            wc = age_stanza(
                "share",
                &[
                    es.index.to_string(),
                    base64encode(&es.s),
                    base64encode(&es.t),
                ],
                &[],
            )(wc)?;
            for s in &es.stanzas {
                wc = age_stanza(&s.tag, &s.args, &s.body)(wc)?;
            }
        }
        wc = hmac_line(wc)?;
        Ok(wc)
    }
}
