use crate::group::{DLogGroup, Element};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use std::fmt::Debug;

pub mod ec;
pub mod mult;

pub type CommitterMult = mult::Committer;
pub type CommitterEc = ec::Committer;
pub type CommitMult = mult::Commit;
pub type CommitEc = ec::Commit;

/// A Pedersen Committer is represented here.
///
/// More about this scheme on [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
#[derive(Debug)]
pub struct Committer<E: Element, G: DLogGroup<E>> {
    group: G,
    h: E,
}

pub type Commit<E> = E;

#[derive(Debug)]
pub struct Opening {
    msg: BigNum,
    r: BigNum,
}

impl super::Opening for Opening {}

impl<E: Element> super::Commit for Commit<E> {}

impl<E, G> super::Committer<Commit<E>, Opening> for Committer<E, G>
where
    E: Element,
    G: DLogGroup<E>,
{
    /// Generates a commit c = g^r * h^m, for a given message m.
    ///
    /// # Parameters
    ///
    /// * `msg`: The message.
    fn commit(&mut self, msg: BigNum) -> Result<(Commit<E>, Opening), ErrorStack> {
        //x1 = g^r mod q
        let r = self.group.generate_random_exponent();
        let x1 = self.group.pow(&r);
        //x2 = h^m mod q
        let x2 = self.group.exponentiate(&self.h, &msg);
        let c = self.group.multiply(&x1, &x2);
        let o = Opening { msg, r };
        Ok((c, o))
    }

    fn verify(&mut self, c: Commit<E>, o: Opening) -> Result<bool, ErrorStack> {
        //x1 = g^r mod q
        let r = o.r;
        let x1 = self.group.pow(&r);
        //x2 = h^m mod q
        let x2 = self.group.exponentiate(&self.h, &o.msg);
        let cmt = self.group.multiply(&x1, &x2);
        Ok(self.group.eq(&cmt, &c))
    }
}
