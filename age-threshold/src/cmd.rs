use age_core::format::FileKey;
use age_core::secrecy::ExposeSecret;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

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

use crate::types::{AgeIdentity, AgeRecipient, EncShare, Header, SecretShare};

const PAYLOAD_KEY_LABEL: &[u8] = b"payload";
const NONCE_SIZE: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;

fn read_text_file(path: &str) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let mut v = vec![];
    for l in BufReader::new(file).lines() {
        let line = l?;
        if !line.starts_with('#') {
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
                .to_identity(UiCallbacks)
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

fn for_chunks(
    mut input: BufReader<impl std::io::Read>,
    chunk_size: usize,
    mut f: impl FnMut(u128, bool, &mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    let mut buf = vec![0; chunk_size];
    let mut counter = 0u128;
    loop {
        let mut n = 0;
        while n < buf.len() {
            match input.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(m) => n += m,
                Err(err) => return Err(err),
            }
        }
        if n < buf.len() || input.fill_buf()?.is_empty() {
            buf.truncate(n);
            f(counter, true, &mut buf)?;
            break;
        }
        f(counter, false, &mut buf)?;
        counter += 1;
    }
    Ok(())
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
            let recipient = r.to_recipient(UiCallbacks).map_err(io::Error::other)?;
            let share_key = new_file_key();
            let mut buf = [0; 68];
            s.serialize(&mut buf);
            let mut buf = buf.to_vec();
            let aead =
                ChaCha20Poly1305::new(&hkdf(&[], b"", &share_key.expose_secret()[..]).into());
            aead.encrypt_in_place((&[0; 12]).into(), b"", &mut buf)
                .map_err(io::Error::other)?;
            let shares = recipient
                .wrap_file_key(&share_key)
                .map_err(io::Error::other)?;
            enc_shares.push(EncShare {
                ciphertext: buf,
                stanzas: shares,
            });
        }

        let out = std::io::stdout();
        let (mut out, _) = cookie_factory::gen(
            format::write::header(threshold as usize, &commitments, &enc_shares),
            out,
        )
        .map_err(io::Error::other)?;

        let mut nonce = [0; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let payload_key = &hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, file_key.expose_secret());
        out.write_all(&nonce)?;

        let aead = ChaCha20Poly1305::new(payload_key.into());
        let input = BufReader::new(io::stdin());
        for_chunks(input, CHUNK_SIZE, |counter, last_chunk, buf| {
            let mut iv = [0; 12];
            iv[..11].copy_from_slice(&counter.to_le_bytes()[..11]);
            iv[11] = last_chunk as u8;
            aead.encrypt_in_place((&iv).into(), b"", buf)
                .map_err(io::Error::other)?;
            out.write_all(buf)
        })
    }

    fn do_decrypt(&self) -> io::Result<()> {
        let mut identities = vec![];
        for id in &self.identity {
            let lines = read_text_file(id)?;
            identities.push(AgeIdentity::from_bech32(&lines[0]).map_err(io::Error::other)?);
        }

        let mut input = BufReader::new(io::stdin());
        fn header(input: &[u8]) -> nom::IResult<&[u8], Header, nom::error::Error<Vec<u8>>> {
            format::read::header(input).map_err(|err| err.to_owned())
        }
        let header = input.parse(header).map_err(|err| match err {
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
                let aead =
                    ChaCha20Poly1305::new(&hkdf(&[], b"", &file_key.expose_secret()[..]).into());
                let mut buf = es.ciphertext;
                aead.decrypt_in_place((&[0; 12]).into(), b"", &mut buf)
                    .map_err(io::Error::other)?;
                let share = SecretShare::deserialize(
                    &buf.try_into().or(Err(io::Error::other("wrong size")))?,
                );
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
        input.read_exact(&mut nonce)?;
        let payload_key = &hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, file_key.expose_secret());
        let aead = ChaCha20Poly1305::new(payload_key.into());

        let mut out = std::io::stdout();
        for_chunks(input, CHUNK_SIZE + TAG_SIZE, |counter, last_chunk, buf| {
            let mut iv = [0; 12];
            iv[..11].copy_from_slice(&counter.to_le_bytes()[..11]);
            iv[11] = last_chunk as u8;
            aead.decrypt_in_place((&iv).into(), b"", buf)
                .map_err(io::Error::other)?;
            out.write_all(buf)
        })
    }
}
