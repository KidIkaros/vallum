// SPDX-License-Identifier: Apache-2.0

//! Suite-dependent tests and benchmarks, kept outside the inner circles.
//!
//! `vallum-core` and `vallum-tunnel` depend on the `CryptoSuite` abstraction and
//! nothing else. Their protocol tests need a concrete suite, so they live here —
//! a component that depends *outward* on the adapter, exactly as the contract
//! crate does for the primitive boundary. This keeps the Dependency Rule true
//! for the libraries and still tests the real suite.
