mod identity;
mod recipient;

use age_core::format::Stanza;

use curve25519_dalek::ristretto::RistrettoPoint;

pub use identity::AgeIdentity;
pub use recipient::AgeRecipient;

#[derive(Debug)]
pub struct Header {
    pub threshold: usize,
    pub commitments: Vec<RistrettoPoint>,
    pub enc_shares: Vec<EncShare>,
}

#[derive(Debug)]
pub struct EncShare {
    pub index: u32,
    pub ciphertext: Vec<u8>,
    pub stanzas: Vec<Stanza>,
}
