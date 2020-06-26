use crate::group::{DLogGroup, Element};
use openssl::error::ErrorStack;
use std::fmt::Debug;

pub mod mult;

pub type CommitterMult = mult::Committer;
pub type CommMult = mult::Comm;

/// A Pedersen Committer is represented here.
///
/// More about this scheme on [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
#[derive(Debug)]
pub struct Committer<E: Element, G: DLogGroup<E>> {
    group: G,
    h: E,
}

pub type Comm<E> = E;
#[derive(Debug)]
pub struct Opening<E: Element> {
    msg: E,
    r: E,
}

impl<E: Element> super::Opening for Opening<E> {}

impl<E: Element> super::Commit for Comm<E> {}

impl<E, G> super::Committer<E, Comm<E>, Opening<E>> for Committer<E, G>
where
    E: Element + super::Message,
    G: DLogGroup<E>,
{
    /// Generates a commit c = g^r * h^m, for a given message m.
    ///
    /// # Parameters
    ///
    /// * `msg`: The message.
    fn commit(&mut self, msg: E) -> Result<(Comm<E>, Opening<E>), ErrorStack> {
        //x1 = g^r mod q
        let r = self.group.generate_random();
        let x1 = self.group.pow(&r);
        //x2 = h^m mod q
        let x2 = self.group.exponentiate(&self.h, &msg);
        let c = self.group.multiply(&x1, &x2);
        let o = Opening { msg, r };
        Ok((c, o))
    }

    fn verify(&mut self, c: Comm<E>, o: Opening<E>) -> Result<bool, ErrorStack> {
        //x1 = g^r mod q
        let r = o.r;
        let x1 = self.group.pow(&r);
        //x2 = h^m mod q
        let x2 = self.group.exponentiate(&self.h, &o.msg);
        let cmt = self.group.multiply(&x1, &x2);
        Ok(cmt == c)
    }
}
