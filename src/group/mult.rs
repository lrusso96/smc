use crate::utils::gen_random;
use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;
use std::fmt;

/// Represents the multiplicative group Zp*, where p is a safe prime.
///
/// A safe prime p is such that p = 2q + 1, for a prime p. Note that when p is
/// a safe prime, the multiplicative group of numbers modulo p has a subgroup
/// of large prime order.
pub struct MultiplicativeGroup {
    // a temporary storage for BigNums
    ctx: BigNumContext,
    // the generator of the group
    g: BigNum,
    // the order of the group
    q: BigNum,
    // modulus
    p: BigNum,
}

impl MultiplicativeGroup {
    #[allow(dead_code)]
    pub fn new(secpar: i32) -> Result<Self, ErrorStack> {
        // create context to manage the bignum
        let mut ctx = BigNumContext::new()?;

        // generate prime safe number p = 2q + 1
        let mut p = BigNum::new()?;
        p.generate_prime(secpar, true, None, None)?;

        //compute order q
        let q = compute_order(&p, &mut ctx)?;

        // Rabin Test (not really mandatory, since we use a safe prime)
        dbg!(q.is_prime(64, &mut ctx).unwrap());
        dbg!(p.is_prime(64, &mut ctx).unwrap());

        // generate random g (generator)
        let _g = gen_random(&p)?;
        let mut g = BigNum::new()?;
        g.mod_exp(&_g, &BigNum::from_u32(2).unwrap(), &p, &mut ctx)?;
        Ok(Self { ctx, g, q, p })
    }
}

fn compute_order(p: &BigNum, ctx: &mut BigNumContext) -> Result<BigNum, ErrorStack> {
    let mut p_minus_one = BigNum::new()?;
    p_minus_one.checked_sub(p, &BigNum::from_u32(1).unwrap())?;
    let mut q = BigNum::new()?;
    q.checked_div(&p_minus_one, &BigNum::from_u32(2).unwrap(), ctx)?;
    Ok(q)
}

impl super::Element for BigNum {}

impl fmt::Debug for MultiplicativeGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Multiplicative Group")
            .field("g", &self.g)
            .field("q", &self.q)
            .finish()
    }
}

impl super::DLogGroup<BigNum> for MultiplicativeGroup {
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
        ret.mod_exp(&e1, &e2, &self.p, &mut self.ctx).unwrap();
        ret
    }

    fn multiply(&mut self, e1: &BigNum, e2: &BigNum) -> BigNum {
        let mut ret = BigNum::new().unwrap();
        ret.mod_mul(&e1, &e2, &self.p, &mut self.ctx).unwrap();
        ret
    }

    fn pow(&mut self, pow: &BigNum) -> BigNum {
        let g1 = BigNum::from_u32(0).unwrap();
        let mut g2 = BigNum::new().unwrap();
        g2.checked_add(&g1, &self.get_generator()).unwrap();
        self.exponentiate(&g2, &pow)
    }
}
