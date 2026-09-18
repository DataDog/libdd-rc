package libddrcffi

// ffiLibHash is set to am sha256 hash of the FFI binary this binary was build
// with, causing a cache invalidation whenever the FFI library is changed.
var ffiLibHash string
