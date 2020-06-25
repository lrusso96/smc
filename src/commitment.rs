use openssl::bn::BigNum;
use openssl::error::ErrorStack;

mod elgamal;
mod pedersen;
pub use elgamal::ElGamalCommitter;
pub use pedersen::PedersenCommitter;

pub trait Committer {
    fn commit(&mut self, msg: BigNum) -> Result<BigNum, ErrorStack>;
    //fn decommit(&self) -> (BigNum, BigNum);
}

#[cfg(test)]
mod tests {

    use super::{Committer, ElGamalCommitter, PedersenCommitter};
    use openssl::bn::BigNum;
    #[test]
    fn test_pedersen() {
        println!("Hello, let's try this Pedersen commit!");
        let sec = 32;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = PedersenCommitter::new(sec).unwrap();
        println!("{:#?}", commiter);
        let msg = BigNum::from_u32(100).unwrap();
        print!("The commit for {} is: ", msg);
        let ret = commiter.commit(msg).unwrap();
        println!("{}", ret);
    }

    #[test]
    fn test_elgamal() {
        println!("Hello, let's try this El-Gamal commit!");
        let sec = 32;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = ElGamalCommitter::new(sec).unwrap();
        println!("{:#?}", commiter);
        let msg = BigNum::from_u32(100).unwrap();
        print!("The commit for {} is: ", msg);
        let ret = commiter.commit(msg).unwrap();
        println!("{}", ret);
    }
}
