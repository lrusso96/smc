use crate::utils::gen_random;
use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;
use std::fmt;

pub struct MultGroup {
    /// a temporary storage for BigNums
    ctx: BigNumContext,
    /// the generator of the group
    g: BigNum,
    /// the order of the group
    q: BigNum,
}

impl MultGroup {
    #[allow(dead_code)]
    pub fn new(secpar: i32) -> Result<Self, ErrorStack> {
        // create context to manage the bignum
        let ctx = BigNumContext::new()?;
        // generate prime safe number q = 2p + 1
        let mut q = BigNum::new()?;
        q.generate_prime(secpar, true, None, None)?;
        // generate random g (generator)
        let g = gen_random(&q)?;
        Ok(Self { ctx, g, q })
    }
}

impl super::Element for BigNum {}

impl fmt::Debug for MultGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Multiplicative Group")
            .field("g", &self.g)
            .field("q", &self.q)
            .finish()
    }
}

impl super::DDHGroup<BigNum> for MultGroup {
    fn get_generator(&self) -> &BigNum {
        &self.g
    }

    fn get_order(&self) -> &BigNum {
        &self.q
    }

    fn generate_random(&self) -> BigNum {
        gen_random(&self.get_order()).unwrap()
    }

    fn exponentiate(&mut self, e1: &BigNum, e2: &BigNum) -> BigNum {
        let mut ret = BigNum::new().unwrap();
        ret.mod_exp(&e1, &e2, &self.q, &mut self.ctx).unwrap();
        ret
    }

    fn multiply(&mut self, e1: &BigNum, e2: &BigNum) -> BigNum {
        let mut ret = BigNum::new().unwrap();
        ret.mod_mul(&e1, &e2, &self.q, &mut self.ctx).unwrap();
        ret
    }

    fn pow(&mut self, pow: &BigNum) -> BigNum {
        let g1 = BigNum::from_u32(0).unwrap();
        let mut g2 = BigNum::new().unwrap();
        g2.checked_add(&g1, &self.get_generator()).unwrap();
        self.exponentiate(&g2, &pow)
    }
}
