use crate::group::{DDHGroup, Element};
use openssl::error::ErrorStack;
use std::fmt::Debug;

pub mod mult;

pub type CommitterMult = mult::Committer;
pub type CommMult = mult::Comm;

#[derive(Debug)]
/// El-Gamal Committer is represented here
pub struct Committer<E: Element, G: DDHGroup<E>> {
    group: G,
    h: E,
}

#[derive(Debug)]
pub struct Comm<E: Element> {
    c1: E,
    c2: E,
}

impl<E: Element> super::Comm for Comm<E> {}

impl<E: Element + super::Value, G: DDHGroup<E>> super::Committer<Comm<E>, E> for Committer<E, G> {
    fn commit(&mut self, msg: E) -> Result<Comm<E>, ErrorStack> {
        //c1 = g^r mod q
        let r = self.group.generate_random();
        let c1 = self.group.pow(&r);
        //c2 = h^r * g^m mod q
        let x1 = self.group.multiply(&self.h, &r);
        let x2 = self.group.pow(&msg);
        let c2 = self.group.multiply(&x1, &x2);
        Ok(Comm { c1, c2 })
    }
}
