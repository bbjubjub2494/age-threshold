use age_core::format::FileKey;
use age_core::secrecy::ExposeSecret;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use curve25519_dalek::Scalar;
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

use crate::types::{AgeIdentity, AgeRecipient, EncShare, Header};

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
    threshold: Option<u32>,
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

fn decrypt_fk(identities: &[AgeIdentity], es: &EncShare) -> io::Result<Option<FileKey>> {
    for identity in identities {
        for s in &es.stanzas {
            match identity
                .to_identity(UiCallbacks {})
                .map_err(io::Error::other)?
                .unwrap_stanza(s)
            {
                Some(Ok(file_key)) => return Ok(Some(file_key)),
                Some(Err(err)) => return Err(io::Error::other(err)),
                None => continue,
            }
        }
    }
    Ok(None)
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
            recipients.push(AgeRecipient::from_bech32(r.as_str()).map_err(io::Error::other)?);
        }
        let n = recipients.len() as u32;
        let threshold = self.threshold.unwrap_or(n / 2 + 1);

        if n < threshold {
            return Err(io::Error::other("not enough recipients"));
        }

        let file_key = new_file_key();
        let (shares, commitments) = crypto::share_secret(&file_key, threshold, n);
        let mut enc_shares = vec![];
        for (r, s) in recipients.iter().zip(shares.iter()) {
            let recipient = r.to_recipient(UiCallbacks {}).map_err(io::Error::other)?;
            let share_key = new_file_key();
            let mut buf = vec![0; 64];
            buf[..32].copy_from_slice(&s.s.to_bytes());
            buf[32..].copy_from_slice(&s.t.to_bytes());
            let aead = chacha20poly1305::ChaCha20Poly1305::new(
                &hkdf(&[], b"", &share_key.expose_secret()[..]).into(),
            );
            aead.encrypt_in_place((&[0; 12]).into(), b"", &mut buf)
                .map_err(|err| io::Error::other(err))?;
            let shares = recipient
                .wrap_file_key(&share_key)
                .map_err(io::Error::other)?;
            enc_shares.push(EncShare {
                index: s.index,
                ciphertext: buf.into(),
                stanzas: shares,
            });
        }

        let out = std::io::stdout();
        let (mut out, _) = cookie_factory::gen(
            format::write::header(threshold as usize, &commitments, &enc_shares),
            out,
        )
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
            identities.push(AgeIdentity::from_bech32(&lines[0]).map_err(io::Error::other)?);
        }

        let mut stdin = BufReader::new(io::stdin());
        fn header(input: &[u8]) -> nom::IResult<&[u8], Header, nom::error::Error<Vec<u8>>> {
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
        for es in header.enc_shares {
            if shares.len() >= header.threshold {
                break;
            }

            if let Some(file_key) = decrypt_fk(&identities, &es)? {
                let aead = chacha20poly1305::ChaCha20Poly1305::new(
                    &hkdf(&[], b"", &file_key.expose_secret()[..]).into(),
                );
                let mut buf = es.ciphertext;
                aead.decrypt_in_place((&[0; 12]).into(), b"", &mut buf)
                    .map_err(|err| io::Error::other(err))?;
                let share = crypto::SecretShare {
                    s: Scalar::from_bytes_mod_order(buf[..32].try_into().unwrap()),
                    t: Scalar::from_bytes_mod_order(buf[32..].try_into().unwrap()),
                    index: es.index,
                };
                if !crypto::verify_share(&share, &header.commitments) {
                    return Err(io::Error::other("invalid share"));
                }
                shares.push(share);
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
