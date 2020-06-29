//!Utilities for secure random number generation. This is a simple wrapper of
//! OpenSSL rand module.

use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;

/// Generates a random `BigNum` between 1 and `limit` - 1.
pub fn rand_range(limit: &BigNum) -> Result<BigNum, ErrorStack> {
    let one = BigNum::from_u32(1)?;
    let mut tmp = BigNum::new()?;
    tmp.checked_sub(limit, &one)?;
    let mut r = BigNum::new()?;
    tmp.rand_range(&mut r)?;
    Ok(r)
}

/// Generates a random `BigNum` with `secpar` bits.
pub fn rand(secpar: i32) -> Result<BigNum, ErrorStack> {
    let mut big = BigNum::new()?;
    big.rand(secpar, MsbOption::MAYBE_ZERO, true)?;
    Ok(big)
}
