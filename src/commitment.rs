use openssl::bn::BigNum;
use openssl::error::ErrorStack;

pub mod elgamal;
pub mod pedersen;

pub type ElGamalCommMult = elgamal::CommMult;
pub type ElGamalCommitterMult = elgamal::CommitterMult;
pub type PedersenCommMult = pedersen::CommMult;
pub type PedersenCommitterMult = pedersen::CommitterMult;

pub trait Value {}
pub trait Comm {}

//impl Comm for BigNum {}
impl Value for BigNum {}

pub trait Committer<C: Comm, V: Value> {
    fn commit(&mut self, msg: V) -> Result<C, ErrorStack>;
    //fn decommit(&self) -> (BigNum, BigNum);
}

#[cfg(test)]
mod tests {

    use super::{Committer, ElGamalCommitterMult, PedersenCommitterMult};
    use openssl::bn::BigNum;
    #[test]
    fn test_pedersen() {
        println!("Hello, let's try this Pedersen commit!");
        let sec = 32;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = PedersenCommitterMult::new(sec).unwrap();
        println!("{:#?}", commiter);
        let msg = BigNum::from_u32(100).unwrap();
        print!("The commit for {} is: ", msg);
        let ret: BigNum = commiter.commit(msg).unwrap();
        println!("{}", ret);
    }

    #[test]
    fn test_elgamal() {
        println!("Hello, let's try this El-Gamal commit!");
        let sec = 32;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = ElGamalCommitterMult::new(sec).unwrap();
        println!("{:#?}", commiter);
        let msg = BigNum::from_u32(100).unwrap();
        print!("The commit for {} is: ", msg);
        let ret = commiter.commit(msg).unwrap();
        println!("{:#?}", ret);
    }
}
