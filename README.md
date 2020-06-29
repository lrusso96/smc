# smc 

[![Build Status](https://travis-ci.com/lrusso96/smc.svg?branch=master)](https://travis-ci.com/lrusso96/smc)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A simple Rust crate for commitment schemes.

[Documentation](https://lrusso96.github.io/smc/smc/index.html).

## About
This crate provides a simple implementation of notable (academic) commitment
schemes, on top of the popular [OpenSSL](https://www.openssl.org/) cryptography library.

This is mostly an exercise to learn Rust. I took inspiration from the
Secure Multiparty Computation class (@Sapienza Univerity of Rome).

## Supported commitment schemes

* El Gamal
* Pedersen

They can be used on top of groups where Discrete Logaritm problem is
assumed to be hard: currently, the crate supports both Multiplicative
Group Zp*, for a safe prime p, and Elliptic Curve.