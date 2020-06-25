use openssl::bn::BigNum;
use openssl::error::ErrorStack;

/// Generates a random `BigNum` between 1 and limit - 1.
pub fn gen_random(limit: &BigNum) -> Result<BigNum, ErrorStack> {
    let one = BigNum::from_u32(1)?;
    let mut tmp = BigNum::new()?;
    tmp.checked_sub(limit, &one)?;
    let mut r = BigNum::new()?;
    tmp.rand_range(&mut r)?;
    Ok(r)
}
