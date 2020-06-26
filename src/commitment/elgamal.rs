use crate::group::{DLogGroup, Element};
use openssl::error::ErrorStack;
use std::fmt::Debug;

pub mod mult;

pub type CommitterMult = mult::Committer;
pub type CommitMult = mult::Commit;

#[derive(Debug)]
/// El-Gamal Committer is represented here
pub struct Committer<E: Element, G: DLogGroup<E>> {
    group: G,
    h: E,
}

#[derive(Debug)]
pub struct Commit<E: Element> {
    c1: E,
    c2: E,
}

impl<E: Element> super::Commit for Commit<E> {}

#[derive(Debug)]
pub struct Opening<E: Element> {
    msg: E,
    r: E,
}

impl<E: Element> super::Opening for Opening<E> {}

impl<E, G> super::Committer<E, Commit<E>, Opening<E>> for Committer<E, G>
where
    E: Element + super::Message,
    G: DLogGroup<E>,
{
    /// Computes the commit as a tuple (c1, c2), where c1 = g^r and c2 = h^r *
    /// g^m
    fn commit(&mut self, msg: E) -> Result<(Commit<E>, Opening<E>), ErrorStack> {
        //c1 = g^r mod q
        let r = self.group.generate_random();
        let c1 = self.group.pow(&r);
        //c2 = h^r * g^m mod q
        let x1 = self.group.multiply(&self.h, &r);
        let x2 = self.group.pow(&msg);
        let c2 = self.group.multiply(&x1, &x2);
        let c = Commit { c1, c2 };
        let o = Opening { msg, r };
        Ok((c, o))
    }

    fn verify(&mut self, c: Commit<E>, o: Opening<E>) -> Result<bool, ErrorStack> {
        //c1 = g^r mod q
        let r = o.r;
        let c1 = self.group.pow(&r);

        //c2 = h^r * g^m mod q
        let x1 = self.group.multiply(&self.h, &r);
        let x2 = self.group.pow(&o.msg);
        let c2 = self.group.multiply(&x1, &x2);
        Ok(c1 == c.c1 && c2 == c.c2)
    }
}
