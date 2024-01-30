use age_core::format::{FileKey, FILE_KEY_BYTES};
use age_core::secrecy::{ExposeSecret, Secret, Zeroize};
use gf256::shamir::shamir;

#[derive(Debug)]
pub struct SecretShare(Secret<[u8; SHARE_BYTES]>);

impl ExposeSecret<[u8; SHARE_BYTES]> for SecretShare {
    fn expose_secret(&self) -> &[u8; SHARE_BYTES] {
        self.0.expose_secret()
    }
}

// FIXME: there is an assumption that one of the bytes is actually an index, make that explicit
const SHARE_BYTES: usize = 17;

pub fn share_secret(fk: &FileKey, t: usize, n: usize) -> Vec<SecretShare> {
    shamir::generate(fk.expose_secret(), n, t)
        .iter_mut()
        .map(|share| {
            assert!(share.len() == SHARE_BYTES);
            let mut buf = [0u8; SHARE_BYTES];
            buf.copy_from_slice(&share[..]);
            share.zeroize();
            SecretShare(Secret::new(buf))
        })
        .collect()
}

pub fn reconstruct_secret(shares: &[SecretShare]) -> FileKey {
    let mut secret = shamir::reconstruct(
        shares
            .iter()
            .map(|share| share.0.expose_secret().as_slice())
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
