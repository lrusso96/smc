use crate::utils::rand;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use std::fmt;

pub struct EllipticCurveGroup {
    group: EcGroup,
    // a temporary storage for BigNums
    ctx: BigNumContext,
    secpar: i32,
}

impl EllipticCurveGroup {
    #[allow(dead_code)]
    pub fn new(secpar: i32, nid: Nid) -> Result<Self, ErrorStack> {
        // create context to manage the bignum
        let ctx = BigNumContext::new()?;

        let group = EcGroup::from_curve_name(nid)?;
        Ok(Self { group, ctx, secpar })
    }
}

impl super::Element for EcPoint {}

impl fmt::Debug for EllipticCurveGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Elliptic Curve Group")
            .field("name", &self.group.curve_name())
            .field("degree", &self.group.degree())
            .finish()
    }
}

impl super::DLogGroup<EcPoint> for EllipticCurveGroup {
    fn get_generator(&self) -> &EcPoint {
        todo!()
    }

    /// returns a copy!
    fn get_order(&mut self) -> BigNum {
        let mut order = BigNum::new().unwrap();
        self.group.order(&mut order, &mut self.ctx).unwrap();
        order.to_owned().unwrap()
    }

    fn generate_random_element(&self) -> EcPoint {
        let m = BigNum::from_u32(100).unwrap();
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.mul(&self.group, self.group.generator(), &m, &self.ctx)
            .unwrap();
        ret
    }

    fn generate_random_exponent(&self) -> BigNum {
        rand(self.secpar).unwrap()
    }

    // this is indeed multiplication
    fn exponentiate(&mut self, e1: &EcPoint, e2: &BigNum) -> EcPoint {
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.mul(&self.group, e1, e2, &mut self.ctx).unwrap();
        ret
    }

    // this is actually the sum
    fn multiply(&mut self, e1: &EcPoint, e2: &EcPoint) -> EcPoint {
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.add(&self.group, e1, e2, &mut self.ctx).unwrap();
        ret
    }

    // this is indeed multiplication for generator
    fn pow(&mut self, pow: &BigNum) -> EcPoint {
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.mul_generator(&self.group, pow, &mut self.ctx).unwrap();
        ret
    }

    fn eq(&mut self, e1: &EcPoint, e2: &EcPoint) -> bool {
        e1.eq(&self.group, e2, &mut self.ctx).unwrap()
    }
}
