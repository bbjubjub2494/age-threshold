use age_core::format::{FileKey, FILE_KEY_BYTES};
use age_core::secrecy::{ExposeSecret, Zeroize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use sha2::Sha512;

static GENERATORS: Lazy<(RistrettoPoint, RistrettoPoint)> = Lazy::new(|| {
    let g = RistrettoPoint::hash_from_bytes::<Sha512>(b"age-threshold pedersen generator G");
    let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"age-threshold pedersen generator H");
    (g, h)
});

fn commit(s: &Scalar, t: &Scalar) -> RistrettoPoint {
    let (g, h) = *GENERATORS;
    g * s + h * t
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
    for c in coeffs {
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
    let s_coeffs: Vec<_> = (0..k)
        .map(|i| {
            if i == 0 {
                s0
            } else {
                Scalar::random(&mut OsRng)
            }
        })
        .collect();
    let t_coeffs: Vec<_> = (0..k).map(|_| Scalar::random(&mut OsRng)).collect();

    let mut shares = vec![];
    for index in 1..=n {
        let s = poly_eval(&s_coeffs, Scalar::from(index));
        let t = poly_eval(&t_coeffs, Scalar::from(index));
        let share = SecretShare { index, s, t };
        shares.push(share);
    }

    let coeff_commitments = s_coeffs
        .iter()
        .zip(t_coeffs.iter())
        .map(|(s, t)| commit(s, t))
        .collect();
    (shares, coeff_commitments)
}

pub fn verify_share(share: &SecretShare, coeff_commitments: &Vec<RistrettoPoint>) -> bool {
    let lhs = commit(&share.s, &share.t);
    let mut rhs = coeff_commitments[0];
    let mut acc = Scalar::ONE;
    for c in &coeff_commitments[1..] {
        acc *= Scalar::from(share.index);
        rhs += c * acc;
    }
    lhs == rhs
}

pub fn reconstruct_secret(shares: &[SecretShare]) -> FileKey {
    // Lagrange interpolation
    // L(x) = Σ yᵢ * lᵢ(x)
    // lᵢ(x) = Π (x - xⱼ) / (xᵢ - xⱼ)
    // s_0 = L(0) = Σ yᵢ * lᵢ(0)
    // lᵢ(0) = Π -xⱼ / (xᵢ - xⱼ)
    // lᵢ(0) = Π xⱼ / (xⱼ - xᵢ)

    let mut s = Scalar::ZERO;
    for (i, share) in shares.iter().enumerate() {
        let mut l_0 = Scalar::ONE;
        let x_i = Scalar::from(share.index);
        for (j, other) in shares.iter().enumerate() {
            if i != j {
                let x_j = Scalar::from(other.index);
                if x_j == x_i {
                    panic!("duplicate share");
                }
                l_0 *= x_j * (x_j - x_i).invert();
            }
        }
        s += share.s * l_0;
    }
    decode(&s)
}

#[cfg(test)]
mod tests {
    use super::{reconstruct_secret, share_secret, verify_share};
    use age_core::format::{FileKey, FILE_KEY_BYTES};
    use age_core::secrecy::ExposeSecret;

    #[test]
    fn test_reconstruct_example() {
        let actual = [0x9; FILE_KEY_BYTES];
        let t = 3;
        let n = 5;
        let (shares, _) = share_secret(&FileKey::from(actual), t, n);

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
            assert!(verify_share(&share, &commitments));
        }
    }
}
