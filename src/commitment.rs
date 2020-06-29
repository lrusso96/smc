use openssl::bn::BigNum;
use openssl::error::ErrorStack;

pub mod elgamal;
pub mod pedersen;

pub type ElGamalCommitMult = elgamal::CommitMult;
pub type ElGamalCommitterMult = elgamal::CommitterMult;
pub type ElGamalCommitEc = elgamal::CommitEc;
pub type ElGamalCommitterEc = elgamal::CommitterEc;
pub type PedersenCommitMult = pedersen::CommitMult;
pub type PedersenCommitterMult = pedersen::CommitterMult;
pub type PedersenCommitEc = pedersen::CommitEc;
pub type PedersenCommitterEc = pedersen::CommitterEc;

pub trait Message {}
pub trait Commit {}
pub trait Opening {}

impl Message for BigNum {}

pub trait Committer<C: Commit, O: Opening> {
    fn commit(&mut self, msg: BigNum) -> Result<(C, O), ErrorStack>;
    fn verify(&mut self, c: C, o: O) -> Result<bool, ErrorStack>;
}

#[cfg(test)]
mod tests {

    use super::Committer;
    use openssl::bn::BigNum;

    #[test]
    fn test_pedersen_mult() {
        use super::PedersenCommitterMult;
        println!("Hello, let's try this Pedersen commit!");
        let sec = 128;
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
    fn test_pedersen_ec() {
        use super::PedersenCommitterEc;
        println!("Hello, let's try this Pedersen commit!");
        let sec = 128;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = PedersenCommitterEc::new(sec).unwrap();
        let msg = BigNum::from_u32(456).unwrap();
        let (c, o) = commiter.commit(msg).unwrap();
        assert_eq!(commiter.verify(c, o).unwrap(), true);
    }

    #[test]
    fn test_elgamal_mult() {
        use super::ElGamalCommitterMult;
        println!("Hello, let's try this El-Gamal commit!");
        let sec = 128;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = ElGamalCommitterMult::new(sec).unwrap();
        println!("{:#?}", commiter);
        let msg = BigNum::from_u32(789).unwrap();
        print!("The commit for {} is: ", msg);
        let (c, o) = commiter.commit(msg).unwrap();
        println!("{:#?}", c);
        assert_eq!(commiter.verify(c, o).unwrap(), true);
    }

    #[test]
    fn test_elgamal_ec() {
        use super::ElGamalCommitterEc;
        println!("Hello, let's try this El-Gamal commit!");
        let sec = 128;
        println!("I'm gonna use {} bits security", sec);
        let mut commiter = ElGamalCommitterEc::new(sec).unwrap();
        let msg = BigNum::from_u32(1011).unwrap();
        let (c, o) = commiter.commit(msg).unwrap();
        assert_eq!(commiter.verify(c, o).unwrap(), true);
    }
}
