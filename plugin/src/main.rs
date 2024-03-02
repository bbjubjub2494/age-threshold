use age_core::format::{AgeStanza, FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use cookie_factory::combinator::slice;
use cookie_factory::{GenResult, WriteContext};
use nom_bufreader::bufreader::BufReader;
use nom_bufreader::Parse;

use age::cli_common::UiCallbacks;
use age::Identity;
use age_core::format;
use age_core::primitives::hkdf;
use clap::{arg, command, ArgAction::SetTrue, Command, Parser};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::str::FromStr;
use std::string::String;
use std::sync::mpsc::{Receiver, Sender};

use age_plugin_threshold::crypto::{self, SecretShare};

use age_plugin_threshold::types::GenericIdentity;
use age_plugin_threshold::types::GenericRecipient;

const PAYLOAD_KEY_LABEL: &[u8] = b"payload";
const NONCE_SIZE: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;

fn read_text_file(path: &str) -> io::Result<Vec<String>> {
    use std::io::BufReader;
    let file = File::open(path)?;
    let mut v = vec![];
    for l in BufReader::new(file).lines() {
        let line = l?;
        if !line.starts_with("#") {
            v.push(line.trim().to_string());
        }
    }
    Ok(v)
}

pub fn new_file_key() -> FileKey {
    let mut buf = [0; 16];
    OsRng.fill_bytes(&mut buf);
    FileKey::from(buf)
}

#[derive(clap::Parser)]
#[command(name = "three")]
#[command(bin_name = "three")]
struct Cli {
    #[clap(short, long)]
    encrypt: bool,
    #[clap(short, long)]
    decrypt: bool,
    #[clap(short, long)]
    threshold: Option<usize>,
    #[clap(short, long)]
    recipient: Vec<String>,
    #[clap(short, long)]
    identity: Vec<String>,
}

use nom::bytes::streaming::tag;

fn main() -> io::Result<()> {
    /* AGE:
     * Usage:
     *    age [--encrypt] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]
     *    age [--encrypt] --passphrase [--armor] [-o OUTPUT] [INPUT]
     *    age --decrypt [-i PATH]... [-o OUTPUT] [INPUT]
     *
     * Options:
     *    -e, --encrypt               Encrypt the input to the output. Default if omitted.
     *    -d, --decrypt               Decrypt the input to the output.
     *    -o, --output OUTPUT         Write the result to the file at path OUTPUT.
     *    -a, --armor                 Encrypt to a PEM encoded format.
     *    -p, --passphrase            Encrypt with a passphrase.
     *    -r, --recipient RECIPIENT   Encrypt to the specified RECIPIENT. Can be repeated.
     *    -R, --recipients-file PATH  Encrypt to recipients listed at PATH. Can be repeated.
     *    -i, --identity PATH         Use the identity file at PATH. Can be repeated.
     */
    let cmd = Cli::parse();

    let mut recipients = vec![];
    for r in cmd.recipient {
        recipients.push(GenericRecipient::from_bech32(r.as_str()).map_err(io::Error::other)?);
    }

    let mut identities = vec![];
    for id in cmd.identity {
        let lines = read_text_file(&id)?;
        identities.push(GenericIdentity::from_bech32(&lines[0]).map_err(io::Error::other)?);
    }

    if cmd.encrypt && cmd.decrypt {
        return Err(io::Error::other(
            "cannot encrypt and decrypt at the same time",
        ));
    }

    if !cmd.decrypt {
        let threshold = cmd.threshold.unwrap_or(recipients.len() / 2 + 1);

        if recipients.len() < threshold {
            return Err(io::Error::other("not enough recipients"));
        }

        let callbacks = UiCallbacks {};
        let file_key = new_file_key();
        let shares = crypto::share_secret(&file_key, threshold, recipients.len());
        let mut shares_stanzas = vec![];
        for (r, s) in recipients.iter().zip(shares.iter()) {
            let recipient = r.to_recipient(callbacks).map_err(io::Error::other)?;
            let mut r = recipient
                .wrap_file_key(&s.file_key)
                .map_err(io::Error::other)?;
            if r.len() != 1 {
                return Err(io::Error::other("encryption produced multiple stanzas"));
            }
            let stanza = r.remove(0);
            shares_stanzas.push(stanza);
        }
        let out = std::io::stdout();
        let (mut out, _) = cookie_factory::gen(serialize(threshold, &shares_stanzas), out)
            .map_err(io::Error::other)?;

        // TODO: handle multiple chunks
        let mut buf = vec![0; CHUNK_SIZE];
        let n = std::io::stdin().read(&mut buf[..])?;
        buf.truncate(n);
        let mut nonce = [0; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let payload_key = hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, file_key.expose_secret()).into();
        let aead = chacha20poly1305::ChaCha20Poly1305::new(&payload_key);
        aead.encrypt_in_place((&[0; 12]).into(), b"", &mut buf)
            .map_err(|err| io::Error::other(err))?;
        out.write_all(&nonce)?;
        out.write_all(&buf)?;
    } else {
        let callbacks = UiCallbacks {};
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let prelude = reader.parse(deserialize).map_err(|err| match err {
            nom_bufreader::Error::Error(err) => {
                io::Error::new(io::ErrorKind::InvalidData, "parse error")
            }
            nom_bufreader::Error::Failure(err) => {
                io::Error::new(io::ErrorKind::InvalidData, "parse error")
            }
            nom_bufreader::Error::Io(err) => err,
            nom_bufreader::Error::Eof => {
                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof")
            }
        })?;
        dbg!(&prelude);
        let mut shares = vec![];
        for (i, s) in prelude.shares_stanzas.iter().enumerate() {
            if shares.len() >= prelude.threshold {
                break;
            }
            for identity in &identities {
                match identity
                    .to_identity(callbacks)
                    .map_err(io::Error::other)?
                    .unwrap_stanza(&s)
                {
                    Some(Ok(file_key)) => {
                        let share = SecretShare {
                            file_key,
                            index: (i + 1).try_into().unwrap(),
                        };
                        shares.push(share);
                        break;
                    }
                    Some(Err(err)) => return Err(io::Error::other(err)),
                    None => continue,
                }
            }
        }
        dbg!(shares.len());
        if shares.len() < prelude.threshold {
            return Err(io::Error::other("not enough shares"));
        }
        let file_key = crypto::reconstruct_secret(&shares);
        let mut nonce = [0; NONCE_SIZE];
        reader.read_exact(&mut nonce)?;
        let payload_key = hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, file_key.expose_secret()).into();
        let aead = chacha20poly1305::ChaCha20Poly1305::new(&payload_key);
        let mut buf = vec![0; CHUNK_SIZE];
        let n = reader.read(&mut buf[..])?;
        buf.truncate(n);
        aead.decrypt_in_place((&[0; 12]).into(), b"", &mut buf)
            .map_err(|err| io::Error::other(err))?;
        io::stdout().write_all(&buf)?;
    }

    Ok(())
}

#[derive(Debug)]
struct Prelude {
    threshold: usize,
    shares_stanzas: Vec<Stanza>,
}

fn serialize<W: Write>(
    t: usize,
    shares_stanzas: &Vec<Stanza>,
) -> impl Fn(WriteContext<W>) -> GenResult<W> + '_ {
    move |mut wc| {
        wc = format::write::age_stanza("threshold", &[&t.to_string()], &[])(wc)?;
        for s in shares_stanzas {
            wc = format::write::age_stanza(&s.tag, &s.args, &s.body)(wc)?;
        }
        wc = slice(&b"---")(wc)?;
        Ok(wc)
    }
}

fn deserialize<'a>(input: &[u8]) -> nom::IResult<&[u8], Prelude, nom::error::Error<Vec<u8>>> {
    match deserialize2(input) {
        Ok((input, prelude)) => Ok((input, prelude)),
        Err(err) => Err(err.to_owned()),
    }
}
fn deserialize2<'a>(input: &[u8]) -> nom::IResult<&[u8], Prelude, nom::error::Error<&[u8]>> {
    let (input, stanza) = format::read::age_stanza(input)?;
    if stanza.tag != "threshold" {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    let threshold = stanza.args[0].parse::<usize>().map_err(|err| {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Satisfy,
        ))
    })?;
    let (input, (mut stanzas, _)) =
        nom::multi::many_till(format::read::age_stanza, tag("---"))(input)?;
    /*
    loop {
        match format::read::age_stanza(input) {
            Ok((input_, stanza)) => {
                input = input_;
                dbg!(stanzas.len());
                dbg!(input.len());
                stanzas.push(stanza.into());
            },
            Err(nom::Err::Incomplete(needed)) => return Err(nom::Err::Incomplete(needed)),
            Err(err) => { dbg!(err); break; }
        };
    }
    */
    Ok((
        input,
        Prelude {
            threshold,
            shares_stanzas: stanzas.drain(..).map(|s| s.into()).collect(),
        },
    ))
}
