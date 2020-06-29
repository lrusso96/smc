use crate::utils::rand;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use std::fmt;

/// A simple wrapper of EcGroup.
///
/// It also manages the context for BigNum operations.
///
/// In order to create a new EllipticCurveGroup, you can use [`new`].
///
/// [`new`]: struct.EllipticCurveGroup.html#method.new
pub struct EllipticCurveGroup {
    group: EcGroup,
    // a temporary storage for BigNums
    ctx: BigNumContext,
    // security parameter
    secpar: i32,
}

impl EllipticCurveGroup {
    #[allow(dead_code)]
    /// Creates a new EllipticCurveGroup.
    ///
    /// # Parameters
    ///
    /// * `secpar`: Length of the security parameter in bits.
    /// * `nid`: The numerical identifier for the curve. These curves can be
    /// discovered using using openssl binary `openssl ecparam -list_curves`.
    ///
    /// # Examples
    ///
    /// ```
    /// use smc::group::{DLogGroup, EllipticCurveGroup};
    /// use openssl::error::ErrorStack;
    /// use openssl::nid::Nid;
    ///
    /// let group = EllipticCurveGroup::new(128, Nid::SECP224R1);
    /// println!("{:#?}", group.unwrap());
    pub fn new(secpar: i32, nid: Nid) -> Result<Self, ErrorStack> {
        // create context to manage the bignum
        let ctx = BigNumContext::new()?;

        // create the group
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

    /// Get the order of the group.
    ///
    /// Note: this returns a clone, not a reference to the object.
    fn get_order(&mut self) -> BigNum {
        let mut order = BigNum::new().unwrap();
        self.group.order(&mut order, &mut self.ctx).unwrap();
        order.to_owned().unwrap()
    }

    /// Generates a random element in the group.
    fn generate_random_element(&self) -> EcPoint {
        let m = rand(self.secpar).unwrap();
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.mul(&self.group, self.group.generator(), &m, &self.ctx)
            .unwrap();
        ret
    }

    /// Generates a random exponent.
    fn generate_random_exponent(&self) -> BigNum {
        rand(self.secpar).unwrap()
    }

    /// Despite its name, this method performs a multiplication on the curve.
    fn exponentiate(&mut self, e1: &EcPoint, e2: &BigNum) -> EcPoint {
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.mul(&self.group, e1, e2, &mut self.ctx).unwrap();
        ret
    }

    // Despite its name, this method performs the sum.
    fn multiply(&mut self, e1: &EcPoint, e2: &EcPoint) -> EcPoint {
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.add(&self.group, e1, e2, &mut self.ctx).unwrap();
        ret
    }

    // Despite its name, this method performs a multiplication for generator.
    fn pow(&mut self, pow: &BigNum) -> EcPoint {
        let mut ret = EcPoint::new(&self.group).unwrap();
        ret.mul_generator(&self.group, pow, &mut self.ctx).unwrap();
        ret
    }

    fn eq(&mut self, e1: &EcPoint, e2: &EcPoint) -> bool {
        e1.eq(&self.group, e2, &mut self.ctx).unwrap()
    }
}
