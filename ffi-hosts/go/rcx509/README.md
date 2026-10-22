# rcx509

`rcx509` is the public Go API for libdd-rc. It manages a Remote Config
x509 connection for you — dial, handshake, reconnect, and dispatch — behind
three calls.

## Integration notes

`rcx509` uses cgo. The current Go binding uses libdd-rc's default FIPS build,
so downstream builds must use `CGO_ENABLED=1` and provide native artifacts
built from the same libdd-rc revision as the Go module:

- `libdd_rc.h` on the C compiler's include path
- `librc_x509_ffi.a` on the native linker's library path
- the version-agnostic AWS-LC FIPS module (`libaws_lc_fips_crypto.so` on
  Linux or `libaws_lc_fips_crypto.dylib` on macOS) on both the linker path and
  the runtime loader path.

These native artifacts are not included in the Go module. From a full
libdd-rc checkout, `make -C ffi-hosts/go build` builds and stages them under
`target/release`. Consumers using another build or packaging system should
include the header and libraries into paths visible to their compiler,
linker, and runtime loader.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

const debugServicePingURI = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

func main() {
	// WithAPIKey is optional; when set, the key is sent in the DD-API-KEY
	// header on every connection attempt.
	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws", "my-app", "0.0.1", rcx509.WithAPIKey(os.Getenv("DD_API_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	// Register a handler for a fully-qualified gRPC method name.
	if err := client.RegisterHandler(debugServicePingURI, handlePing); err != nil {
		log.Fatal(err)
	}

	// Start blocks, reconnecting as needed, until Close is called.
	go client.Start()

	fmt.Println("Press Enter to exit...")
	fmt.Scanln()

	client.Close()
}

func handlePing(correlationID uint64, payload []byte) ([]byte, error) {
	// payload is a protobuf message, and so is the return value.
	// 
	// Unmarshal the payload, do stuff, marshal a response and return it.

	response := []byte("bananas")
	return response, nil
}
```

That's it!

See [`cmd/testx509`](../cmd/testx509) for a complete, runnable example that
wires up a real handler.

See the [module README](../README.md) for build instructions.
