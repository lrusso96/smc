use crate::utils::gen_random;
use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;
use std::fmt;

/// El-Gamal Committer is represented here
pub struct ElGamalCommitter {
    /// a temporary storage for BigNums
    ctx: BigNumContext,
    /// the generator of the group
    g: BigNum,
    /// the order of the group
    q: BigNum,
    /// a random (public) element of the group
    h: BigNum,
}

impl fmt::Debug for ElGamalCommitter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElGamalCommitter")
            .field("g", &self.g)
            .field("q", &self.q)
            .field("h", &self.h)
            .finish()
    }
}

impl ElGamalCommitter {
    /// Generates a new instance of El-Gamal Committer.
    ///
    /// # Parameters
    ///
    /// * `secpar`: The number of bits for prime number generation.
    ///
    /// # Examples
    ///
    ///```
    ///use smc::commitment::{Committer, ElGamalCommitter};
    ///use openssl::bn::BigNum;
    ///fn main() {
    ///    println!("Hello, let's try this El-Gamal commit!");
    ///    let sec = 32;
    ///    println!("I'm gonna use {} bits security", sec);
    ///    let mut commiter = ElGamalCommitter::new(sec).unwrap();
    ///    println!("{:#?}", commiter);
    ///    let msg = BigNum::from_u32(100).unwrap();
    ///    print!("The commit for {} is: ", msg);
    ///    let ret = commiter.commit(msg).unwrap();
    ///    println!("{}", ret);
    ///}
    /// ```
    #[allow(dead_code)]
    pub fn new(secpar: i32) -> Result<ElGamalCommitter, ErrorStack> {
        // create context to manage the bignum
        let ctx = BigNumContext::new()?;
        // generate prime safe number q = 2p + 1
        let mut q = BigNum::new()?;
        q.generate_prime(secpar, true, None, None)?;
        // generate random g (generator)
        let g = gen_random(&q)?;
        // generate random element h
        let h = gen_random(&q)?;
        Ok(Self { ctx, g, q, h })
    }
}

impl super::Committer for ElGamalCommitter {
    /// Generates a commit on a given message.
    ///
    /// # Parameters
    ///
    /// * `msg`: The message.
    fn commit(&mut self, msg: BigNum) -> Result<BigNum, ErrorStack> {
        //c1 = g^r mod q
        let r = gen_random(&self.q)?;
        let mut c1 = BigNum::new()?;
        c1.mod_exp(&self.g, &r, &self.q, &mut self.ctx)?;
        //c2 = h^r * g^m mod q
        let mut x1 = BigNum::new()?;
        x1.mod_exp(&self.h, &r, &self.q, &mut self.ctx)?;
        let mut x2 = BigNum::new()?;
        x2.mod_exp(&self.g, &msg, &self.q, &mut self.ctx)?;
        let mut ret = BigNum::new()?;
        ret.mod_mul(&x1, &x2, &self.q, &mut self.ctx)?;
        Ok(ret)
    }
}
