use openssl::bn::BigNum;
use openssl::error::ErrorStack;

pub mod elgamal;
pub mod pedersen;

pub type ElGamalCommitMult = elgamal::CommitMult;
pub type ElGamalCommitterMult = elgamal::CommitterMult;
pub type PedersenCommitMult = pedersen::CommitMult;
pub type PedersenCommitterMult = pedersen::CommitterMult;

pub trait Message {}
pub trait Commit {}
pub trait Opening {}

impl Message for BigNum {}

pub trait Committer<M, C, O>
where
    M: Message,
    C: Commit,
    O: Opening,
{
    fn commit(&mut self, msg: M) -> Result<(C, O), ErrorStack>;
    fn verify(&mut self, c: C, o: O) -> Result<bool, ErrorStack>;
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
        let msg = BigNum::from_u32(123).unwrap();
        print!("The commit for {} is: ", msg);
        let (c, o) = commiter.commit(msg).unwrap();
        println!("{}", c);
        assert_eq!(commiter.verify(c, o).unwrap(), true);
    }

    #[test]
    fn test_elgamal() {
        println!("Hello, let's try this El-Gamal commit!");
        let sec = 32;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = ElGamalCommitterMult::new(sec).unwrap();
        println!("{:#?}", commiter);
        let msg = BigNum::from_u32(456).unwrap();
        print!("The commit for {} is: ", msg);
        let (c, o) = commiter.commit(msg).unwrap();
        println!("{:#?}", c);
        assert_eq!(commiter.verify(c, o).unwrap(), true);
    }
}
