use crate::group::{DLogGroup, MultiplicativeGroup};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;

pub type Committer = super::Committer<BigNum, MultiplicativeGroup>;
pub type Commit = super::Commit<BigNum>;

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
    ///
    /// println!("Hello, let's try this Pedersen commit!");
    /// let sec = 128;
    ///println!("I'm gonna use {} bits security", sec);
    ///let mut commiter = PedersenCommitterMult::new(sec).unwrap();
    ///println!("{:#?}", commiter);
    ///let msg = BigNum::from_u32(100).unwrap();
    ///print!("The commit for {} is: ", msg);
    ///let (c, _) = commiter.commit(msg).unwrap();
    ///println!("{}", c);
    /// ```
    #[allow(dead_code)]
    pub fn new(secpar: i32) -> Result<Committer, ErrorStack> {
        let group = MultiplicativeGroup::new(secpar)?;
        let h = group.generate_random_element();
        Ok(Self { group, h })
    }
}
