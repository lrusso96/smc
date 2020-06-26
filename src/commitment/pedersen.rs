use crate::group::{DLogGroup, Element};
use openssl::error::ErrorStack;
use std::fmt::Debug;

pub mod mult;

pub type CommitterMult = mult::Committer;
pub type CommMult = mult::Comm;

/// A Pedersen Committer is represented here
#[derive(Debug)]
pub struct Committer<E: Element, G: DLogGroup<E>> {
    group: G,
    h: E,
}

pub type Comm<E> = E;

impl<E: Element> super::Comm for Comm<E> {}

impl<E: Element + super::Value, G: DLogGroup<E>> super::Committer<Comm<E>, E> for Committer<E, G> {
    /// Generates a commit on a given message.
    ///
    /// # Parameters
    ///
    /// * `msg`: The message.
    fn commit(&mut self, msg: E) -> Result<Comm<E>, ErrorStack> {
        //x1 = g^r mod q
        let r = self.group.generate_random();
        let x1 = self.group.pow(&r);
        //x2 = h^m mod q
        let x2 = self.group.exponentiate(&self.h, &msg);
        Ok(self.group.multiply(&x1, &x2))
    }
}
