//! Opaque identifiers of specific [`Certificate`] instances.
//!
//! The IDs in this module are untrusted values, and can be set to anything the
//! cert issuer wishes. Derived values such as a [`KeyId`] or certificate
//! [`Fingerprint`]) SHOULD be preferred for general use.
//!
//! The only real use for these values is chain building: the [`IssuerCertId`]
//! and [`CertId`] values embedded in [`Certificate`] instances form a chain
//! from the root, where the [`SubjectKeyId`] (SKI) value of an issuing CA
//! certificate is embedded in a child certificate as an [`IssuerCertId`] (AKI)
//! value:
//!
//! ```text
//!                ╔═ Root ════════════════════════╗
//!                ║ ┌───────────────────────────┐ ║
//!                ║ │ Authority Key Identifier  │ ║
//!                ║ └───────────────────────────┘ ║
//!                ║ ┌───────────────────────────┐ ║
//!                ║ │  Subject Key Identifier   │━━━━┓
//!                ║ └───────────────────────────┘ ║  ┃
//!                ╚═══════════════════════════════╝  ┃
//!                                                   ┃
//!                                                   ┃
//!                ╔═ Intermediate ════════════════╗  ┃
//!                ║ ┌───────────────────────────┐ ║  ┃
//!                ║ │ Authority Key Identifier  │◀━━━┛
//!                ║ └───────────────────────────┘ ║
//!                ║ ┌───────────────────────────┐ ║
//!                ║ │  Subject Key Identifier   │━━━━┓
//!                ║ └───────────────────────────┘ ║  ┃
//!                ╚═══════════════════════════════╝  ┃
//!                                                   ┃
//!                                                   ┃
//!                ╔═ Leaf Certificate ════════════╗  ┃
//!                ║ ┌───────────────────────────┐ ║  ┃
//!                ║ │ Authority Key Identifier  │◀━━━┛
//!                ║ └───────────────────────────┘ ║
//!                ║ ┌───────────────────────────┐ ║
//!                ║ │  Subject Key Identifier   │ ║
//!                ║ └───────────────────────────┘ ║
//!                ╚═══════════════════════════════╝
//! ```
//!
//! The [`CertId`] (SKI) value of a signer SHOULD be embedded into any child
//! certificates as the [`IssuerCertId`] value (AKI).
//!
//! While the SKI and AKI are documented in [RFC 5280] as being a hash of the
//! respective certificate's public key, in practice the SKI / AKI value is
//! often truncated, or replaced entirely with identifiers that are not derived
//! in any way from the public key (e.g. `hash(dn + serial_number`)). For this
//! reason, they are used by our system as opaque (potentially forged)
//! identifiers only and like a [`SerialNumber`] MUST NOT be used as an equality
//! check - prefer a [`Fingerprint`] instead.
//!
//! [`Certificate`]: super::Certificate
//! [`SerialNumber`]: super::SerialNumber
//! [`Fingerprint`]: super::Fingerprint
//! [`KeyId`]: crate::keys::KeyId
//! [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280

mod cert_id;
mod dangerous_comparible;
mod issuer_cert_id;

pub use cert_id::*;
pub use dangerous_comparible::*;
pub use issuer_cert_id::*;
