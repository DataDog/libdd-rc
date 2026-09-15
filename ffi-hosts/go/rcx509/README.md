# rcx509

`rcx509` is the public Go API for libdd-rc. It manages a Remote Config
x509 connection for you — dial, handshake, reconnect, and dispatch — behind
three calls.

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

const debugServicePingURI = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

func main() {
	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws", "my-app", "0.0.1")
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
