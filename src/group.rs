use std::fmt;

mod mult;

pub use mult::MultGroup;

pub trait DDHGroup<E: Element>: fmt::Debug {
    fn get_generator(&self) -> &E;
    fn get_order(&self) -> &E;

    fn generate_random(&self) -> E;

    //add methods for exponentiation

    fn exponentiate(&mut self, e1: &E, e2: &E) -> E;
    fn multiply(&mut self, e1: &E, e2: &E) -> E;
    fn pow(&mut self, pow: &E) -> E;
}

pub trait Element {}
