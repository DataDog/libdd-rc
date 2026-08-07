package ddrc

// NOTE: rc-crypto defaults to the "fips" feature, and AWS-LC's FIPS-validated
// crypto module ships only as a shared object (never a static archive) since
// it must verify its own binary at load time. librc_x509_ffi.a is linked
// statically, but the FIPS crypto module must still be linked dynamically;
// `make libffi` copies it next to librc_x509_ffi.a in target/release so the
// -L/-rpath below can find it without extra runtime configuration. The
// -laws_lc_fips_0_13_16_crypto name is version-pinned to the aws-lc-fips-sys
// version in Cargo.lock and must be updated if that version changes (run
// `cargo rustc -p rc-x509-ffi --release --crate-type staticlib --
// --print=native-static-libs` from the repo root to find the current name).

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../target/release -lrc_x509_ffi -laws_lc_fips_0_13_16_crypto -liconv -framework CoreFoundation -framework Security -lm -Wl,-rpath,${SRCDIR}/../../../target/release
#cgo linux LDFLAGS: -L${SRCDIR}/../../../target/release -lrc_x509_ffi -laws_lc_fips_0_13_16_crypto -lpthread -ldl -lm -Wl,-rpath,${SRCDIR}/../../../target/release
#include "libdd_rc.h"
*/
import "C"
