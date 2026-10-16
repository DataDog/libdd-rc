# WASM Client

This folder contains a `build.sh` that compiles `rc-x509-ffi` as a WASM module,
using the WASIp1 interface.

This is a **proof-of-concept** and CI gate to ensure building WASM binaries is
possible - it is **not actively supported** - if you want to ship WASM builds of
this client please let us know.


## Building

The following are required:

* The `wasm32-wasip1-threads` rust compilation target (use `rustup`).
* An LLVM toolchain (NOT Apple's shipped version, install via `brew`).
* A WASI sysroot.

See the [CI build image] and [WASM workflow] for examples.


### WASI

The resulting binary uses WASI for access to:

  * Randomness
  * System clock
  * File descriptors (log sink)
  * Threading

All of these can be worked around with a bit of time and effort, which would
result in a pure WASM binary (no WASI dependency). This might be necessary, as
threading in particular has patchy support and is [officially abandoned].

[CI build image]: ../../.github/images/rust-ci.Dockerfile
[WASM workflow]: ../../.github/workflows/wasm.yml
[officially abandoned]: https://github.com/WebAssembly/wasi-threads