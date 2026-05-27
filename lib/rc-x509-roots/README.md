# rc-x509-roots

This crate contains the RC X509 root certificates ([R1] and [R2]).

These certificates are exported as PEM-encoded strings, and as an initialised
[`RootCertificate`] type wrapper over a [`Certificate`] for convenience.

## Inspect

You can inspect each root using OpenSSL:

```shellsession
% openssl x509 -noout -text -fingerprint -sha256 -in r1.crt
```

The output of this command for each root is included as a doc comment on the
respective exported [`RootCertificate`].

[R1]: r1.crt
[R2]: r2.crt
[`RootCertificate`]: crate::RootCertificate
[`Certificate`]: rc_crypto::certificate::Certificate
