use openssl::bn::BigNum;

mod ec;
mod mult;

pub use ec::EllipticCurveGroup;
pub use mult::MultiplicativeGroup;

/// This is the trait for groups where Discrete Log (**DL**) problem is
/// considered to be hard.
///
/// DL problem: given a generator `g` of a finite group `G` and
/// a random element `h` in `G`, find the integer x such that g^x = h.
/// The two most common classes in cryptographic applications are the
/// multiplicative group Zp* for a large prime p, and some Elliptic curve group.
///
/// For more details check [here](https://en.wikipedia.org/wiki/Discrete_logarithm).
pub trait DLogGroup<E: Element> {
    /// Retrieves the generator `g` for the group.
    fn get_generator(&self) -> &E;

    /// Returns the order of the group.
    fn get_order(&mut self) -> BigNum;

    /// Generates a random element in the group.
    fn generate_random_element(&self) -> E;

    /// Generates a random exponent
    fn generate_random_exponent(&self) -> BigNum;

    /// Computes an exponentiation between two elements in the group.
    fn exponentiate(&mut self, e1: &E, e2: &BigNum) -> E;

    /// Computes the multiplication between two elements in the group.
    fn multiply(&mut self, e1: &E, e2: &E) -> E;

    /// Computes the pow.
    fn pow(&mut self, pow: &BigNum) -> E;

    /// Compares two elements in a group.
    fn eq(&mut self, e1: &E, e2: &E) -> bool;
}

/// This trait represents an element of a group.
pub trait Element {}
