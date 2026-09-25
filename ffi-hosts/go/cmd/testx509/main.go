package main

import (
	"fmt"
	"log"
	"os"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

// debugServicePingURI is the fully-qualified gRPC method name for the
// Remote Config team's example DebugService/Ping RPC.
const debugServicePingURI = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

func main() {
	enableLogging()

	// Connect to the Datadog DC, reporting this application as:
	//
	//  Name: testx509-poc
	//  Version: 0.0.1
	//
	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws", "testx509-poc", "0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	// Register a handler for the DebugService/Ping URI:
	if err := client.RegisterHandler(debugServicePingURI, handlePing); err != nil {
		log.Fatal(err)
	}

	go client.Start()

	fmt.Println("Press Enter to exit...")
	fmt.Scanln()

	client.Close()
}

func enableLogging() {
	const ENV = "RC_LOG"

	// Set the log level to "debug" if nothing was specified (library defaults
	// to "info").
	if _, ok := os.LookupEnv(ENV); !ok {
		os.Setenv(ENV, "debug")
	}

	// Emit the client library's own tracing output on stderr.
	if err := rcx509.EnableLogSink(os.Stderr); err != nil {
		log.Fatal(err)
	}
}
