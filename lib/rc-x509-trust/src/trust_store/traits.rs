use std::sync::Arc;

use rc_crypto::certificate::{Certificate, id::CertId};

/// A [`CertCache`] holds [`Certificate`] instances locally, making them
/// available for retrieval and removal by their [`CertId`].
///
/// # Panics
///
/// Implementations guarantee a stable mapping of [`CertId`] to [`Certificate`],
/// panicking if any inconsistent mapping is found under the assumption exactly
/// one [`Certificate`] exists per key.
pub trait CertCache: Send + Sync + std::fmt::Debug + 'static {
    /// Insert `cert`, making it available to subsequent queries using its
    /// [`CertId`].
    fn insert(&mut self, cert: Certificate);

    /// Retrieve a [`Certificate`] by the [`CertId`], if previously inserted.
    fn get(&self, cert_id: &CertId) -> Option<Arc<Certificate>>;

    /// Remove the [`Certificate`] which has the specified [`CertId`], returning
    /// true on success, or false if there is not matching [`Certificate`]
    /// stored.
    fn remove(&mut self, cert_id: &CertId) -> bool;
}
