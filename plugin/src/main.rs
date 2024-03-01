use age_core::format::{FileKey, Stanza, AgeStanza};
use cookie_factory::{WriteContext, GenResult};
use nom_bufreader::bufreader::BufReader;
use nom_bufreader::Parse;

use age::Identity;
use age_core::format;
use age::cli_common::UiCallbacks;
use clap::{Parser,ArgAction::SetTrue, arg, command, Command};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::str::FromStr;
use std::string::String;
use std::sync::mpsc::{Receiver, Sender};

use age_plugin_threshold::crypto::{self, SecretShare};
use rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, RlpStream};

use age_plugin_threshold::types::GenericIdentity;
use age_plugin_threshold::types::GenericRecipient;
use age_plugin_threshold::types::ThresholdIdentity;
use age_plugin_threshold::types::ThresholdRecipient;


struct EncShare {
    index: u8,
    stanzas: Vec<Stanza>,
}

/*
fn read_text_file(path: &str) -> io::Result<Vec::<String>> {
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
*/

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
    recipients: Vec<String>,
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
    for r in cmd.recipients {
                recipients.push(GenericRecipient::from_bech32(r.as_str()).map_err(io::Error::other)?);
    }

    if cmd.encrypt && cmd.decrypt {
        return Err(io::Error::other("cannot encrypt and decrypt at the same time"));
    }

    if cmd.encrypt {
    let threshold = cmd.threshold.unwrap_or(recipients.len()/2+1);

    if recipients.len() < threshold {
        return Err(io::Error::other("not enough recipients"));
    }

    let callbacks = UiCallbacks{};
    let secret = FileKey::from([9; 16]);
    let shares = crypto::share_secret(&secret, threshold, recipients.len());
    let mut enc_shares = vec![];
    for (r,s) in recipients.iter().zip(shares.iter()) {
        let recipient = r.to_recipient(callbacks).map_err(io::Error::other)?;
        let stanzas = recipient.wrap_file_key(&s.file_key).map_err(io::Error::other)?;
        enc_shares.push(EncShare{index: s.index, stanzas});
    }
    let mut wc = cookie_factory::WriteContext{write: std::io::stdout(), position: 0};
    wc = serialize(threshold, &enc_shares)(wc).map_err(io::Error::other)?;
    } else {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let stanzas = reader.parse(deserialize).map_err(|err| match err {
            nom_bufreader::Error::Error(err) => io::Error::new(io::ErrorKind::InvalidData, "parse error"),
            nom_bufreader::Error::Failure(err) => io::Error::new(io::ErrorKind::InvalidData, "parse error"),
            nom_bufreader::Error::Io(err) => err,
            nom_bufreader::Error::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof"),
        })?;
        dbg!(stanzas);
    }

    Ok(())
}

fn serialize<W: Write>(t: usize, enc_shares: &Vec<EncShare>) -> impl Fn(WriteContext<W>) -> GenResult<W> + '_ { move |mut wc| {
    wc = format::write::age_stanza("threshold", &[&t.to_string()], &[])(wc)?;
    for es in enc_shares {
        wc = format::write::age_stanza("share_index", &[&es.index.to_string()], &[])(wc)?;
        for s in &es.stanzas {
            wc = format::write::age_stanza(&s.tag, &s.args, &s.body)(wc)?;
        }
    }
    wc = wc.write(b"---")?;
    Ok(wc)
    }
}

fn deserialize<'a>(input: &[u8]) -> nom::IResult<&[u8], Vec<Stanza>, nom::error::Error<Vec<u8>>> {
    match deserialize2(input) {
        Ok((input, mut stanzas)) => Ok((input, stanzas.drain(..).map(|s| s.into()).collect())),
        Err(err) => Err(err.to_owned())
    }
}
fn deserialize2<'a>(input: &[u8]) -> nom::IResult<&[u8], Vec<AgeStanza>, nom::error::Error<&[u8]>> {
    /*
    (input, stanza) = format::read::age_stanza(input)?;
    if stanza.tag != "threshold" {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }
    */
    // let t = stanza.args[0].parse::<usize>().map_err(|err| nom::error::Error::new(input, nom::error::ErrorKind::ParseInt))?;
    let (input, stanzas) = nom::multi::many_till(format::read::age_stanza, tag("---"))(input)?;
    dbg!(stanzas.len());
    dbg!(input.len());
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
    Ok((input, stanzas))
}
