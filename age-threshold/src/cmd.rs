use age_core::format::FileKey;
use age_core::secrecy::ExposeSecret;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use nom_bufreader::bufreader::BufReader;
use nom_bufreader::Parse;

use age::cli_common::UiCallbacks;
use age_core::primitives::hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::string::String;

use crate::crypto;
use crate::format;

use crate::types::GenericIdentity;
use crate::types::GenericRecipient;

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
pub struct Cli {
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
    #[clap(short, long)]
    armor: bool,
    #[clap(short, long)]
    passphrase: bool,
    #[clap(short = 'R', long)]
    recipients_file: Vec<String>,

    input: Option<String>,
}

impl Cli {
    pub fn main(&self) -> io::Result<()> {
        if self.encrypt && self.decrypt {
            return Err(io::Error::other(
                "cannot encrypt and decrypt at the same time",
            ));
        }

        if self.decrypt {
            self.do_decrypt()
        } else {
            self.do_encrypt()
        }
    }

    fn do_encrypt(&self) -> io::Result<()> {
        let mut recipients = vec![];
        for r in &self.recipient {
            recipients.push(GenericRecipient::from_bech32(r.as_str()).map_err(io::Error::other)?);
        }
        let threshold = self.threshold.unwrap_or(recipients.len() / 2 + 1);

        if recipients.len() < threshold {
            return Err(io::Error::other("not enough recipients"));
        }

        let file_key = new_file_key();
        let shares = crypto::share_secret(&file_key, threshold, recipients.len());
        let mut shares_stanzas = vec![];
        for (r, s) in recipients.iter().zip(shares.iter()) {
            let recipient = r.to_recipient(UiCallbacks {}).map_err(io::Error::other)?;
            let mut r = recipient
                .wrap_file_key(&s.file_key)
                .map_err(io::Error::other)?;
            match r.len() {
                0 => return Err(io::Error::other("plugin produced no stanzas")),
                1 => (),
                _ => return Err(io::Error::other("plugin produced multiple stanzas")),
            }
            let stanza = r.remove(0);
            shares_stanzas.push(stanza);
        }

        let out = std::io::stdout();
        let (mut out, _) =
            cookie_factory::gen(format::write::header(threshold, &shares_stanzas), out)
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

        Ok(())
    }

    fn do_decrypt(&self) -> io::Result<()> {
        let mut identities = vec![];
        for id in &self.identity {
            let lines = read_text_file(&id)?;
            identities.push(GenericIdentity::from_bech32(&lines[0]).map_err(io::Error::other)?);
        }

        let mut stdin = BufReader::new(io::stdin());
        fn header(input: &[u8]) -> nom::IResult<&[u8], format::Header, nom::error::Error<Vec<u8>>> {
            format::read::header(input).map_err(|err| err.to_owned())
        }
        let header = stdin.parse(header).map_err(|err| match err {
            nom_bufreader::Error::Error(_) => {
                io::Error::new(io::ErrorKind::InvalidData, "parse error")
            }
            nom_bufreader::Error::Failure(_) => {
                io::Error::new(io::ErrorKind::InvalidData, "parse error")
            }
            nom_bufreader::Error::Io(err) => err,
            nom_bufreader::Error::Eof => {
                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof")
            }
        })?;

        let mut shares = vec![];
        for (i, s) in header.shares_stanzas.iter().enumerate() {
            if shares.len() >= header.threshold {
                break;
            }
            for identity in &identities {
                match identity
                    .to_identity(UiCallbacks {})
                    .map_err(io::Error::other)?
                    .unwrap_stanza(&s)
                {
                    Some(Ok(file_key)) => {
                        let share = crypto::SecretShare {
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
        if shares.len() < header.threshold {
            return Err(io::Error::other("not enough shares"));
        }
        let file_key = crypto::reconstruct_secret(&shares);

        let mut nonce = [0; NONCE_SIZE];
        stdin.read_exact(&mut nonce)?;
        let payload_key = hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, file_key.expose_secret()).into();
        let aead = chacha20poly1305::ChaCha20Poly1305::new(&payload_key);
        let mut buf = vec![0; CHUNK_SIZE];
        let n = stdin.read(&mut buf[..])?;
        buf.truncate(n);
        aead.decrypt_in_place((&[0; 12]).into(), b"", &mut buf)
            .map_err(|err| io::Error::other(err))?;
        io::stdout().write_all(&buf)?;

        Ok(())
    }
}
