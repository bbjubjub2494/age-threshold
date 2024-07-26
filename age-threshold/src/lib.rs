pub mod crypto;
pub mod format;
pub mod types;

use age::cli_common::UiCallbacks;
use age_core::format::FileKey;
use age_core::secrecy::ExposeSecret;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

use nom_bufreader::bufreader::BufReader;
use nom_bufreader::Parse;

use std::io;
use std::io::prelude::*;

use age_core::primitives::hkdf;
use rand::rngs::OsRng;
use rand::RngCore;

const PAYLOAD_KEY_LABEL: &[u8] = b"payload";
const NONCE_SIZE: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;

pub fn encrypt(
    recipients: &[types::AgeRecipient],
    t: u32,
    input: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<()> {
    let file_key = new_file_key();
    let n = recipients.len() as u32;

    if n < t {
        return Err(io::Error::other("not enough recipients"));
    }

    let (shares, commitments) = crypto::share_secret(&file_key, t, n);
    let mut enc_shares = vec![];
    for (r, s) in recipients.iter().zip(shares.iter()) {
        let recipient = r.to_recipient(UiCallbacks).map_err(io::Error::other)?;
        let share_key = new_file_key();
        let mut buf = [0; 68];
        s.serialize(&mut buf);
        let mut buf = buf.to_vec();
        let mut cipher = ChaCha20::new(
            &hkdf(&[], b"", &share_key.expose_secret()[..]).into(),
            (&[0; 12]).into(),
        );
        cipher.apply_keystream(&mut buf);
        let shares = recipient
            .wrap_file_key(&share_key)
            .map_err(io::Error::other)?;
        enc_shares.push(types::EncShare {
            ciphertext: buf,
            stanzas: shares,
        });
    }

    let (output, _) = cookie_factory::gen(
        format::write::header(t as usize, &commitments, &enc_shares),
        output,
    )
    .map_err(io::Error::other)?;

    let mut nonce = [0; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let payload_key = &hkdf(nonce.as_ref(), PAYLOAD_KEY_LABEL, file_key.expose_secret());
    output.write_all(&nonce)?;

    let aead = ChaCha20Poly1305::new(payload_key.into());
    let input = BufReader::new(input);
    for_chunks(input, CHUNK_SIZE, |counter, last_chunk, buf| {
        let mut iv = [0; 12];
        iv[..11].copy_from_slice(&counter.to_le_bytes()[..11]);
        iv[11] = last_chunk as u8;
        aead.encrypt_in_place((&iv).into(), b"", buf)
            .map_err(io::Error::other)?;
        output.write_all(buf)
    })
}

pub fn decrypt(
    identities: &[types::AgeIdentity],
    input: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<()> {
    let mut input = BufReader::new(input);
    fn header(input: &[u8]) -> nom::IResult<&[u8], types::Header, nom::error::Error<Vec<u8>>> {
        format::read::header(input).map_err(|err| err.to_owned())
    }
    let header = input.parse(header).map_err(|err| match err {
        nom_bufreader::Error::Error(_) => io::Error::new(io::ErrorKind::InvalidData, "parse error"),
        nom_bufreader::Error::Failure(_) => {
            io::Error::new(io::ErrorKind::InvalidData, "parse error")
        }
        nom_bufreader::Error::Io(err) => err,
        nom_bufreader::Error::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof"),
    })?;

    let mut shares = vec![];
    for es in header.enc_shares {
        if shares.len() >= header.threshold {
            break;
        }

        if let Some(share_key) = decrypt_fk(identities, &es)? {
            let mut buf = es.ciphertext;
            let mut cipher = ChaCha20::new(
                &hkdf(&[], b"", &share_key.expose_secret()[..]).into(),
                (&[0; 12]).into(),
            );
            cipher.apply_keystream(&mut buf);
            let share = types::SecretShare::deserialize(
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

    for_chunks(input, CHUNK_SIZE + TAG_SIZE, |counter, last_chunk, buf| {
        let mut iv = [0; 12];
        iv[..11].copy_from_slice(&counter.to_le_bytes()[..11]);
        iv[11] = last_chunk as u8;
        aead.decrypt_in_place((&iv).into(), b"", buf)
            .map_err(io::Error::other)?;
        output.write_all(buf)
    })
}

fn new_file_key() -> FileKey {
    let mut buf = [0; 16];
    OsRng.fill_bytes(&mut buf);
    FileKey::from(buf)
}

fn for_chunks(
    mut input: BufReader<impl Read>,
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

fn decrypt_fk(
    identities: &[types::AgeIdentity],
    es: &types::EncShare,
) -> io::Result<Option<FileKey>> {
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
