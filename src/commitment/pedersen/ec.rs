use crate::group::{DLogGroup, EllipticCurveGroup};
use openssl::ec::EcPoint;
use openssl::error::ErrorStack;
use openssl::nid::Nid;

pub type Committer = super::Committer<EcPoint, EllipticCurveGroup>;
pub type Commit = super::Commit<EllipticCurveGroup>;

impl Committer {
    /// Generates a new instance of Pedersen Committer.
    ///
    /// # Parameters
    ///
    /// * `secpar`: The number of bits for prime number generation.
    ///
    /// # Examples
    ///
    ///```
    ///use smc::commitment::{Committer, PedersenCommitterEc};
    ///use openssl::bn::BigNum;
    ///
    ///println!("Hello, let's try this Pedersen commit!");
    ///let sec = 128;
    ///println!("I'm gonna use {} bits security", sec);
    ///let mut commiter = PedersenCommitterEc::new(sec).unwrap();
    ///let msg = BigNum::from_u32(100).unwrap();
    ///let (c, o) = commiter.commit(msg).unwrap();
    /// ```
    #[allow(dead_code)]
    pub fn new(secpar: i32) -> Result<Committer, ErrorStack> {
        let group = EllipticCurveGroup::new(secpar, Nid::SECP224R1)?;
        let h = group.generate_random_element();
        Ok(Self { group, h })
    }
}
