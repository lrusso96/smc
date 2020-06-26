use crate::group::{DLogGroup, MultGroup};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;

pub type Committer = super::Committer<BigNum, MultGroup>;
pub type Comm = super::Comm<BigNum>;

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
    ///use smc::commitment::{Committer, PedersenCommitterMult};
    ///use openssl::bn::BigNum;
    ///fn main() {
    ///    println!("Hello, let's try this Pedersen commit!");
    ///    let sec = 32;
    ///    println!("I'm gonna use {} bits security", sec);
    ///    let mut commiter = PedersenCommitterMult::new(sec).unwrap();
    ///    println!("{:#?}", commiter);
    ///    let msg = BigNum::from_u32(100).unwrap();
    ///    print!("The commit for {} is: ", msg);
    ///    let ret = commiter.commit(msg).unwrap();
    ///    println!("{}", ret);
    ///}
    /// ```
    #[allow(dead_code)]
    pub fn new(secpar: i32) -> Result<Committer, ErrorStack> {
        let group = MultGroup::new(secpar)?;
        let h = group.generate_random();
        Ok(Self { group, h })
    }
}
