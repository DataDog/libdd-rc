use rc_crypto::{certificate::csr::CertificateSigningRequest, keys::PrivateKey};
use rcgen::{BasicConstraints, GeneralSubtree, IsCa, NameConstraints};

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{TestCertTemplate, sign_tbs},
};

/// An initialisation template for an intermediate CA certificate.
#[derive(Debug)]
pub(crate) struct IntermediateTemplate<'a> {
    parent: &'a Identity,
    allowed_domain: Option<String>,
    path_len: u8,
}

impl<'a> TestCertTemplate for IntermediateTemplate<'a> {
    fn build(self, cn: String, key: PrivateKey) -> Identity {
        let csr = CertificateSigningRequest::new_intermediate(&key, &cn).expect("invalid CSR");

        let mut tbs = rcgen::CertificateSigningRequestParams::from_pem(&csr.as_pem_string())
            .expect("invalid TBS");

        tbs.params.is_ca = IsCa::Ca(BasicConstraints::Constrained(self.path_len));

        tbs.params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(
                self.allowed_domain
                    .expect("must specify name constraint allow domain"),
            )],
            excluded_subtrees: vec![],
        });

        sign_tbs(self.parent, key, tbs)
    }
}

impl<'a> CertBuilder<IntermediateTemplate<'a>> {
    /// Initialise a new intermediate CA template.
    pub(crate) fn new_intermediate(cn: impl Into<String>, parent: &'a Identity) -> Self {
        CertBuilder {
            cn: cn.into(),
            role: IntermediateTemplate {
                parent,
                allowed_domain: None,
                path_len: 0,
            },
        }
    }

    /// Set the permitted NameConstraint domains (required).
    pub(crate) fn allowed_domain(mut self, domain: impl Into<String>) -> Self {
        self.role.allowed_domain = Some(domain.into());
        self
    }

    /// Set the pathLen constraint for the basic constraint CA field (default:
    /// 0).
    pub(crate) fn path_len(mut self, n: u8) -> Self {
        self.role.path_len = n;
        self
    }
}
