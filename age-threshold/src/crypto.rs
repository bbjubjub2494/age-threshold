use age_core::format::{FileKey, FILE_KEY_BYTES};
use age_core::secrecy::{ExposeSecret, Secret, Zeroize};
use gf256::shamir::shamir;

use std::fmt;

pub struct SecretShare {
    pub index: u8,
    pub file_key: FileKey,
}

impl fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretShare")
            .field("index", &self.index)
            .field("file_key", &self.file_key.expose_secret()) // FIXME: dont
            .finish()
    }
}

impl ExposeSecret<[u8; FILE_KEY_BYTES]> for SecretShare {
    fn expose_secret(&self) -> &[u8; FILE_KEY_BYTES] {
        self.file_key.expose_secret()
    }
}

pub fn share_secret(fk: &FileKey, t: usize, n: usize) -> Vec<SecretShare> {
    shamir::generate(fk.expose_secret(), n, t)
        .iter_mut()
        .enumerate()
        .map(|(i, share)| {
            assert!(share.len() == FILE_KEY_BYTES + 1);
            let index: u8 = share[0];
            assert!(usize::from(index) == i + 1);
            let mut buf = [0u8; FILE_KEY_BYTES];
            buf.copy_from_slice(&share[1..]);
            share.zeroize();
            SecretShare {
                index,
                file_key: FileKey::from(buf),
            }
        })
        .collect()
}

pub fn reconstruct_secret(shares: &[SecretShare]) -> FileKey {
    assert!(shares.len() > 0);
    let bufs = shares
        .iter()
        .map(|share| {
            dbg!(share);
            let mut buf = [0u8; FILE_KEY_BYTES + 1];
            buf[0] = share.index;
            buf[1..].copy_from_slice(share.file_key.expose_secret());
            Secret::from(buf)
        })
        .collect::<Vec<_>>();
    let mut secret = shamir::reconstruct(
        bufs.iter()
            .map(|buf| buf.expose_secret())
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let mut buf = [0u8; FILE_KEY_BYTES];
    buf.copy_from_slice(&secret[..]);
    secret.zeroize();
    FileKey::from(buf)
}

#[cfg(test)]
mod tests {
    use super::{reconstruct_secret, share_secret};
    use age_core::format::{FileKey, FILE_KEY_BYTES};
    use age_core::secrecy::ExposeSecret;

    #[test]
    fn test_reconstruct_example() {
        let actual = [0xa; FILE_KEY_BYTES];
        let t = 3;
        let n = 5;
        let shares = share_secret(&FileKey::from(actual), t, n);
        let result = reconstruct_secret(&shares[..]);
        let expected = result.expose_secret();
        assert_eq!(&actual, expected);
    }
}
