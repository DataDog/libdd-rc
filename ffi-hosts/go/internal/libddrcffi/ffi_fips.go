//go:build !rcx509_nonfips

package libddrcffi

// Link the AWS-LC FIPS crypto library built by rc-crypto's default "fips"
// feature. A librc_x509_ffi built with the "non-fips" feature has no such
// library; build with the rcx509_nonfips tag to omit this link.

/*
#cgo LDFLAGS: -laws_lc_fips_crypto
*/
import "C"
