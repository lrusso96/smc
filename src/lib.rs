//! `smc`
//!
//! This crate provides a simple implementation of notable (academic) commitment
//! schemes, on top of the popular [OpenSSL](https://www.openssl.org/) cryptography library.
//!
//! This is mostly an exercise to learn Rust. I took inspiration from the
//! Secure Multiparty Computation class (@Sapienza Univerity of Rome).
//!
//! # Supported commitment schemes
//!
//! * [El Gamal]
//! * [Pedersen]
//!
//! [El Gamal]: commitment/elgamal/struct.Committer.html
//! [Pedersen]: commitment/pedersen/struct.Committer.html
//!
//! They can be used on top of groups where Discrete Logaritm problem is
//! assumed to be hard: currently, the crate supports both [Multiplicative
//! Group Zp*], for a safe prime p, and [Elliptic Curve].
//!
//! [Elliptic Curve]: group/struct.EllipticCurveGroup.html
//! [Multiplicative Group Zp*]: group/struct.MultiplicativeGroup.html
//!

pub mod commitment;
pub mod group;
pub mod utils;
