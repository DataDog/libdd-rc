package libddrcffi

// NOTE: rc-crypto defaults to the "fips" feature, and AWS-LC's FIPS-validated
// crypto module ships only as a shared object (never a static archive) since
// it must verify its own binary at load time. librc_x509_ffi.a is linked
// statically, but the FIPS crypto module must still be linked dynamically;
// `make libffi` copies the version-named lib (e.g.
// libaws_lc_fips_0_13_16_crypto) to the version-agnostic
// libaws_lc_fips_crypto next to librc_x509_ffi.a in target/release, so the
// -laws_lc_fips_crypto link below stays valid across aws-lc-fips-sys version
// bumps in Cargo.lock.

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../../target/release -lrc_x509_ffi -laws_lc_fips_crypto -liconv -framework CoreFoundation -framework Security -lm -Wl,-rpath,${SRCDIR}/../../../../target/release
#cgo linux LDFLAGS: -L${SRCDIR}/../../../../target/release -lrc_x509_ffi -laws_lc_fips_crypto -lpthread -ldl -lm -Wl,-rpath,${SRCDIR}/../../../../target/release
#include "libdd_rc.h"
*/
import "C"
