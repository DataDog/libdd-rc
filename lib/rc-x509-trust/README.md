# rc-x509-trust

This library is responsible for building trust chains, and using them to
authenticate signed messages.

All input is considered as untrusted until proven to be trusted.

## Design Goals

* Only certificates that chain to a known root and are otherwise "valid" (see
  below) are accepted.
* Messages are considered valid iff they are signed by a keypair for which there
  is a trusted certificate.
* Revocation of a certificate revokes any previously established trust, and
  prevents it from being trusted in the future.

## Certificate Validity

A certificate is considered valid iff:

1. It cryptographically chains to a known root, through other valid intermediate
   certificates (if any).
1. The current time is between the `NotBefore` and `NotAfter` validity
   timestamps within the cert.
1. It satisfies any name constraints for the domain being used for RC
   communication.
1. Uses FIPS approved cryptographic algorithms.
1. Has not been previously revoked via CRL.

Additionally, a leaf / payload signer certificate has the following additional
requirements:

1. The certificate has an EKU (Extended Key Usage) for `codeSigning`.
