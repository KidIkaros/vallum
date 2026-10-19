// SPDX-License-Identifier: Apache-2.0

//! Error types for the Vallum cryptographic boundary.
//!
//! These are Vallum's own errors. They intentionally do **not** wrap SDK error
//! types: the adapter maps SDK failures into these, so nothing above the
//! boundary ever names an SDK type.

use core::fmt;

macro_rules! boundary_error {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            /// Create an error with a human-readable reason.
            pub fn new(reason: impl Into<String>) -> Self {
                Self(reason.into())
            }

            /// The reason this error was raised.
            pub fn reason(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}: {}", stringify!($name), self.0)
            }
        }

        impl std::error::Error for $name {}
    };
}

boundary_error!(KemError, "A hybrid-KEM operation failed.");
boundary_error!(KdfError, "A key-derivation operation failed.");
boundary_error!(AeadError, "An AEAD seal/open operation failed.");
boundary_error!(SigError, "A signature operation failed.");
boundary_error!(
    SuiteError,
    "The requested suite is unknown or unsupported by this provider."
);
