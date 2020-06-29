use crate::group::{DLogGroup, Element};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use std::fmt::Debug;

pub mod ec;
pub mod mult;

pub type CommitterMult = mult::Committer;
pub type CommitMult = mult::Commit;
pub type CommitterEc = ec::Committer;
pub type CommitEc = ec::Commit;

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
pub struct Opening {
    msg: BigNum,
    r: BigNum,
}

impl super::Opening for Opening {}

impl<E, G> super::Committer<Commit<E>, Opening> for Committer<E, G>
where
    E: Element,
    G: DLogGroup<E>,
{
    /// Computes the commit as a tuple (c1, c2), where c1 = g^r and c2 = h^r *
    /// g^m
    fn commit(&mut self, msg: BigNum) -> Result<(Commit<E>, Opening), ErrorStack> {
        //c1 = g^r mod q
        let r = self.group.generate_random_exponent();
        let c1 = self.group.pow(&r);
        //c2 = h^r * g^m mod q
        let x1 = self.group.exponentiate(&self.h, &r);
        let x2 = self.group.pow(&msg);
        let c2 = self.group.multiply(&x1, &x2);
        let c = Commit { c1, c2 };
        let o = Opening { msg, r };
        Ok((c, o))
    }

    fn verify(&mut self, c: Commit<E>, o: Opening) -> Result<bool, ErrorStack> {
        //c1 = g^r mod q
        let r = o.r;
        let c1 = self.group.pow(&r);

        //c2 = h^r * g^m mod q
        let x1 = self.group.exponentiate(&self.h, &r);
        let x2 = self.group.pow(&o.msg);
        let c2 = self.group.multiply(&x1, &x2);
        let b1 = self.group.eq(&c1, &c.c1);
        let b2 = self.group.eq(&c2, &c.c2);
        Ok(b1 && b2)
    }
}
