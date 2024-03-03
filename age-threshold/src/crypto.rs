use age_core::format::{FileKey, FILE_KEY_BYTES};
use age_core::secrecy::{ExposeSecret, Secret, Zeroize};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;
use sha2::Sha512;


fn commit(s: &Scalar, t: &Scalar) -> RistrettoPoint {
    // FIXME: pre-compute
let G = RistrettoPoint::hash_from_bytes::<Sha512>(b"age-threshold pedersen generator G");
let H = RistrettoPoint::hash_from_bytes::<Sha512>(b"age-threshold pedersen generator H");
    G * s + H * t
}

fn encode(fk: &FileKey) -> Scalar {
    let mut buf = [0u8; 32];
    // 128-bit file keys fit snugly in the low-order bytes.
    buf[..FILE_KEY_BYTES].copy_from_slice(fk.expose_secret());
    let s = Scalar::from_bytes_mod_order(buf);
    buf.zeroize();
    s
}

fn decode(s: &Scalar) -> FileKey {
    let mut buf = [0u8; FILE_KEY_BYTES];
    buf.copy_from_slice(&s.as_bytes()[..FILE_KEY_BYTES]);
    FileKey::from(buf)
}

fn poly_eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut r = Scalar::ZERO;
    let mut acc = Scalar::ONE;
    for (j, c) in coeffs.iter().enumerate() {
        r += c * acc;
        acc *= x;
    }
    r
}

#[derive(Debug)]
pub struct SecretShare {
    pub index: u32,
    pub s: Scalar,
    pub t: Scalar,
}

pub fn share_secret(fk: &FileKey, k: u32, n: u32) -> (Vec<SecretShare>, Vec<RistrettoPoint>) {
    let s0 = encode(fk);
    let s_coeffs: Vec<_> = (0..k).map(|i| if i == 0 { s0 } else { Scalar::random(&mut OsRng) }).collect();
    let t_coeffs: Vec<_> = (0..k).map(|_| Scalar::random(&mut OsRng)).collect();

    let mut shares = vec![];
    for index in 0..n {
        let s = poly_eval(&s_coeffs, Scalar::from(index));
        let t = poly_eval(&t_coeffs, Scalar::from(index));
        let share = SecretShare { index, s, t };
        shares.push(share);
    }

    let coeff_commitments = s_coeffs.iter().zip(t_coeffs.iter()).map(|(s, t)| commit(s, t)).collect();
    (shares, coeff_commitments)
}

pub fn verify_share(share: SecretShare, coeff_commitments: &Vec<RistrettoPoint>) -> bool {
    let lhs = commit(&share.s, &share.t);
    let mut rhs = coeff_commitments[0];
    let mut acc = Scalar::ONE;
    for (j, c) in coeff_commitments[1..].iter().enumerate() {
        acc *= Scalar::from(share.index);
        rhs += c * acc;
    }
    lhs == rhs
}

pub fn reconstruct_secret(shares: &[SecretShare]) -> FileKey {
    todo!();
}

#[cfg(test)]
mod tests {
    use super::{share_secret, reconstruct_secret, verify_share, SecretShare};
    use age_core::format::{FileKey, FILE_KEY_BYTES};
    use age_core::secrecy::ExposeSecret;

    #[test]
    fn test_reconstruct_example() {
        let actual = [0x9; FILE_KEY_BYTES];
        let t = 3;
        let n = 5;
        let (shares,_) = share_secret(&FileKey::from(actual), t, n);

        let result = reconstruct_secret(&shares[..]);
        let expected = result.expose_secret();
        assert_eq!(&actual, expected);
    }

    #[test]
    fn test_verify_shares() {
        let actual = [0x9; FILE_KEY_BYTES];
        let t = 3;
        let n = 5;
        let (shares, commitments) = share_secret(&FileKey::from(actual), t, n);

        for share in shares {
            assert!(verify_share(share, &commitments));
        }
    }
}
