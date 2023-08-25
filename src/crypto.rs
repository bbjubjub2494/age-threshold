use age_core::secrecy::{Secret,ExposeSecret,Zeroize};
use age_core::format::{FileKey,FILE_KEY_BYTES};
use gf256::shamir::shamir;

pub struct SecretShare(Secret<[u8; FILE_KEY_BYTES]>);
impl SecretShare {
    fn eat(&self, share: &mut [u8; FILE_KEY_BYTES]) -> SecretShare{
        let r = SecretShare(Secret::new(*share));
        share.zeroize();
        r
    }
}

fn share_secret(fk: FileKey, t: usize, n: usize) -> Vec<SecretShare> {
    shamir::generate(fk.expose_secret(), n, t).iter_mut().map_mut(|share| {
        assert!(share.length() == FILE_KEY_BYTES);
        SecretShare::eat(share)
    }).collect()
}
